"""
Static analysis engine.

Given an artifact (loose file, wheel, sdist, or installed package),
the static engine:

  1. Enumerates files within the artifact.
  2. Asks the triage module which files are in scope (or accepts a
     forced file kind for single-file mode).
  3. For each in-scope file, invokes the appropriate parser.
  4. Runs each registered analyzer against the parsed representation.
  5. Evaluates raw signals against the rule set to produce findings.
  6. Returns a ScanResult.

Architecture note (refactor for future parallelism):

The per-file pipeline is implemented as `_scan_one_file`, a pure
function in the call-shape sense: given a `FileScanInput`, it
returns a `FileScanOutput` without mutating engine state. The
artifact-level scan methods drive the pipeline in three phases:

  Phase 1: Enumerate the artifact and build a list of FileScanInput.
  Phase 2: Run `_scan_one_file` over each input. Today serial; this
           is the line that becomes a process pool later.
  Phase 3: Aggregate the per-file FileScanOutputs into a single
           ScanResult.

Deep mode (deep_mode=True at construction):

  Triage classifies ordinary library .py files as `FileKind.LIBRARY_PY`
  instead of skipping them. For LIBRARY_PY files, the engine filters
  analyzers via the `Analyzer.safe_for_library_scan` class attribute,
  running only those analyzers whose signals are calibrated to be
  meaningful outside startup-vector context. Currently this is just
  the density analyzer.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Callable

from pydepgate.analyzers.base import Analyzer, Signal
from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    FileScanOutput,
    FileStatsEntry,
    Finding,
    ScanContext,
    ScanResult,
    ScanStatistics,
    SkippedFile,
    SuppressedFinding,
    confidence_to_severity_v01,
)
from pydepgate.parsers.pth import parse_pth, LineKind
from pydepgate.parsers.pysource import SourceLocation, parse_python_source
from pydepgate.rules.base import evaluate_signal
from pydepgate.traffic_control.triage import FileKind, triage


class StaticEngine:
    """Static analysis engine for pydepgate artifacts.

    The engine is stateless across scans: a single instance can serve
    many scan calls. Analyzers, rules, and the deep_mode flag are
    set at construction time and never mutated afterward.

    The per-file pipeline (`_scan_one_file`) does not touch instance
    state. This is a load-bearing property: when the engine is
    parallelized, worker processes will receive their own copy of
    `self` and any mutation done in a worker would be invisible to
    the parent. Keep it that way.
    """

    def __init__(
        self,
        analyzers: list[Analyzer],
        rules: list | None = None,
        deep_mode: bool = False,
    ) -> None:
        self._analyzers: tuple[Analyzer, ...] = tuple(analyzers)
        # Default to bundled rules if none provided. Allows tests to
        # pass an empty rules list to test pre-rules behavior, and
        # callers can pass custom rules including user rules.
        if rules is None:
            from pydepgate.rules.defaults import DEFAULT_RULES
            rules = list(DEFAULT_RULES)
        self._rules = list(rules)
        self._deep_mode = deep_mode

    @property
    def rules(self) -> list:
        """The rules configured for this engine."""
        return list(self._rules)

    @property
    def analyzers(self) -> tuple[Analyzer, ...]:
        """The analyzers configured for this engine, in registration order."""
        return self._analyzers

    @property
    def deep_mode(self) -> bool:
        """Whether deep-mode triage is enabled for this engine."""
        return self._deep_mode

    # ========================================================================
    # Public per-target entry points
    # ========================================================================

    def scan_file(self, path: Path) -> ScanResult:
        """Scan a single loose file on disk.

        Uses the filename to let triage determine the file's kind,
        then routes to the appropriate parser and analyzer set.
        Returns an empty ScanResult with a diagnostic if the file
        cannot be read.
        """
        try:
            content = path.read_bytes()
        except OSError as exc:
            return ScanResult(
                artifact_identity=str(path),
                artifact_kind=ArtifactKind.LOOSE_FILE,
                findings=(),
                skipped=(),
                statistics=ScanStatistics(),
                diagnostics=(f"failed to read {path}: {exc}",),
            )
        return self.scan_bytes(
            content=content,
            internal_path=path.name,
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity=str(path),
        )

    def scan_bytes(
        self,
        content: bytes,
        internal_path: str,
        artifact_kind: ArtifactKind,
        artifact_identity: str | None = None,
    ) -> ScanResult:
        """Scan a single file's bytes, treated as part of an artifact.

        Triage decides the file kind based on `internal_path`. Used
        internally by the artifact-level scan methods (scan_wheel,
        scan_sdist, scan_installed) and exposed for callers that
        already have content in memory.
        """
        identity = artifact_identity or internal_path
        inp = FileScanInput(
            content=content,
            internal_path=internal_path,
            artifact_kind=artifact_kind,
            artifact_identity=identity,
            forced_file_kind=None,
        )
        output = self._scan_one_file(inp)
        return self._wrap_single_output_as_result(
            identity=identity,
            artifact_kind=artifact_kind,
            output=output,
        )

    def scan_loose_file_as(
        self,
        path: Path,
        file_kind: FileKind,
    ) -> ScanResult:
        """Scan a single loose file on disk, treating it as the given kind.

        Bypasses triage entirely. The file's real path is preserved
        verbatim in the resulting ScanContext, so downstream reports
        reference the actual filename rather than a synthetic
        stand-in. Used by 'pydepgate scan --single' to allow
        iteration testing on arbitrary files without renaming them
        or restructuring directories.

        Args:
            path: Filesystem path to the file. Used both as the
                content source and as the internal_path/
                artifact_identity in the resulting context.
            file_kind: Forced FileKind. Must not be FileKind.SKIP.

        Returns:
            A ScanResult with findings (possibly empty). On read
            failure, returns a ScanResult with an empty finding set
            and a diagnostic explaining the failure.

        Raises:
            ValueError: if file_kind is FileKind.SKIP.
        """
        if file_kind is FileKind.SKIP:
            raise ValueError(
                "scan_loose_file_as cannot be called with FileKind.SKIP; "
                "pass an in-scope kind (PTH, SETUP_PY, INIT_PY, "
                "SITECUSTOMIZE, USERCUSTOMIZE, LIBRARY_PY)."
            )

        try:
            content = path.read_bytes()
        except OSError as exc:
            return ScanResult(
                artifact_identity=str(path),
                artifact_kind=ArtifactKind.LOOSE_FILE,
                findings=(),
                skipped=(),
                statistics=ScanStatistics(),
                diagnostics=(f"failed to read {path}: {exc}",),
            )

        inp = FileScanInput(
            content=content,
            internal_path=str(path),
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity=str(path),
            forced_file_kind=file_kind,
        )
        output = self._scan_one_file(inp)
        return self._wrap_single_output_as_result(
            identity=str(path),
            artifact_kind=ArtifactKind.LOOSE_FILE,
            output=output,
        )

    def scan_wheel(
            self,
            path: Path,
            *,
            progress_callback: Callable[[int, int], None] | None = None,
        ) -> ScanResult:
            """Scan a wheel file by enumerating its entries and analyzing each.

            Args:
                path: Path to the .whl file.
                progress_callback: Optional callable invoked once per file
                    during Phase 2 of the scan, with (completed, total)
                    where total is the number of in-scope files. Used by
                    the CLI to render a progress bar; pass None to scan
                    silently.
            """
            from pydepgate.parsers.wheel import (
                iter_wheel_files_with_diagnostics,
                SkippedEntry as WheelSkippedEntry,
                WheelEntry,
            )
            return self._scan_artifact_with_enumerator(
                identity=str(path),
                artifact_kind=ArtifactKind.WHEEL,
                enumerate_fn=lambda: iter_wheel_files_with_diagnostics(path),
                extract_entry=lambda item: (
                    (item[0].internal_path, item[0].content)
                    if isinstance(item[0], WheelEntry)
                    else None
                ),
                extract_skipped=lambda item: (
                    SkippedFile(
                        internal_path=item[0].raw_name,
                        reason=item[0].reason,
                    )
                    if isinstance(item[0], WheelSkippedEntry)
                    else None
                ),
                progress_callback=progress_callback,
            )

    def scan_sdist(
            self,
            path: Path,
            *,
            progress_callback: Callable[[int, int], None] | None = None,
        ) -> ScanResult:
            """Scan an sdist file by enumerating its entries.

            See scan_wheel for the progress_callback contract.
            """
            from pydepgate.parsers.sdist import (
                iter_sdist_files_with_diagnostics,
                SkippedEntry as SdistSkippedEntry,
                SdistEntry,
            )
            return self._scan_artifact_with_enumerator(
                identity=str(path),
                artifact_kind=ArtifactKind.SDIST,
                enumerate_fn=lambda: iter_sdist_files_with_diagnostics(path),
                extract_entry=lambda item: (
                    (item.internal_path, item.content)
                    if isinstance(item, SdistEntry)
                    else None
                ),
                extract_skipped=lambda item: (
                    SkippedFile(internal_path=item.raw_name, reason=item.reason)
                    if isinstance(item, SdistSkippedEntry)
                    else None
                ),
                progress_callback=progress_callback,
            )
    def scan_installed(
            self,
            package_name: str,
            *,
            progress_callback: Callable[[int, int], None] | None = None,
        ) -> ScanResult:
            """Scan the files of an installed package by name.

            See scan_wheel for the progress_callback contract.
            """
            from pydepgate.introspection.installed import (
                iter_installed_package_files,
                InstalledPackageNotFound,
            )
            try:
                files_iter = iter_installed_package_files(package_name)
            except InstalledPackageNotFound:
                return ScanResult(
                    artifact_identity=package_name,
                    artifact_kind=ArtifactKind.INSTALLED_ENV,
                    findings=(),
                    skipped=(),
                    statistics=ScanStatistics(),
                    diagnostics=(f"package not installed: {package_name}",),
                )
            return self._scan_artifact_with_enumerator(
                identity=package_name,
                artifact_kind=ArtifactKind.INSTALLED_ENV,
                enumerate_fn=lambda: ((f, None) for f in files_iter),
                extract_entry=lambda item: (item[0].internal_path, item[0].content),
                extract_skipped=lambda item: None,
                progress_callback=progress_callback,
            )

    # ========================================================================
    # The per-file pipeline (pure-function spine)
    # ========================================================================

    def _scan_one_file(self, inp: FileScanInput) -> FileScanOutput:
        """Run the per-file scan pipeline. Pure function in call shape.

        Contract (load-bearing for future parallelism):
          1. Does not mutate self. Reads `self._analyzers`,
             `self._rules`, and `self._deep_mode` only.
          2. Inputs and outputs are pickle-safe by construction
             (FileScanInput and FileScanOutput hold only primitives,
             enums, and tuples of frozen dataclasses).
          3. Analyzers invoked here must be stateless across calls
             (enforced by the Analyzer ABC contract).
          4. Rule evaluation is a pure function of the triple
             (signal, context, rules).

        Together these properties mean this method can be called in
        a worker process by a future ProcessPoolExecutor without
        any further changes to the per-file pipeline.

        The forced_file_kind path skips triage entirely; the
        triage path may produce a SKIP output if triage decides
        the file is out of scope.
        """
        started_at = time.perf_counter()

        # Step 1: Resolve the file kind.
        decided_kind, decided_path, decided_reason = self._resolve_file_kind(
            inp,
        )

        # Step 2: Handle the skip cases (whether forced or triaged).
        if decided_kind is FileKind.SKIP:
            duration = time.perf_counter() - started_at
            return FileScanOutput(
                internal_path=inp.internal_path,
                findings=(),
                skipped=(SkippedFile(
                    internal_path=decided_path,
                    reason=decided_reason,
                ),),
                diagnostics=(),
                suppressed_findings=(),
                statistics=ScanStatistics(
                    files_total=1,
                    files_skipped=1,
                    duration_seconds=duration,
                ),
            )

        # Step 3: Build the context and run the analyzer/rule pipeline.
        context = ScanContext(
            artifact_kind=inp.artifact_kind,
            artifact_identity=inp.artifact_identity,
            internal_path=decided_path,
            file_kind=decided_kind,
            triage_reason=decided_reason,
        )
        diagnostics: list[str] = []
        signals = self._analyze_file(
            inp.content, decided_kind, context, diagnostics,
        )

        # Step 4: Evaluate signals against rules.
        findings: list[Finding] = []
        suppressed: list[SuppressedFinding] = []
        for signal in signals:
            result = evaluate_signal(signal, context, self._rules)
            if result.finding is not None:
                findings.append(result.finding)
            elif result.suppressed_finding is not None:
                suppressed.append(SuppressedFinding(
                    original_finding=result.suppressed_finding,
                    suppressing_rule_id=(
                        result.suppressing_rule.rule_id
                        if result.suppressing_rule else "unknown"
                    ),
                    suppressing_rule_source=(
                        result.suppressing_rule.source.value
                        if result.suppressing_rule else "unknown"
                    ),
                    would_have_been=(
                        result.would_have_been or result.suppressed_finding
                    ),
                ))

        duration = time.perf_counter() - started_at
        return FileScanOutput(
            internal_path=inp.internal_path,
            findings=tuple(findings),
            skipped=(),
            diagnostics=tuple(diagnostics),
            suppressed_findings=tuple(suppressed),
            statistics=ScanStatistics(
                files_total=1,
                files_scanned=1,
                signals_emitted=len(signals),
                analyzers_run=len(self._select_analyzers_for_kind(decided_kind)),
                duration_seconds=duration,
            ),
        )

    def _resolve_file_kind(
        self,
        inp: FileScanInput,
    ) -> tuple[FileKind, str, str]:
        """Decide the file kind, resolved path, and reason for an input.

        Returns a triple (kind, internal_path, reason). If
        forced_file_kind is set on the input, that wins; otherwise
        triage decides (using deep_mode if the engine is so configured).
        Defensive: if a caller manages to pass FileKind.SKIP as
        forced_file_kind, this is treated as a SKIP decision and the
        per-file pipeline returns a skip output, rather than crashing.
        """
        if inp.forced_file_kind is not None:
            return (
                inp.forced_file_kind,
                inp.internal_path,
                f"single-file mode: forced kind={inp.forced_file_kind.value}",
            )
        decision = triage(inp.internal_path, deep_mode=self._deep_mode)
        return (decision.kind, decision.internal_path, decision.reason)

    # ========================================================================
    # Analyzer selection
    # ========================================================================

    def _select_analyzers_for_kind(
        self,
        file_kind: FileKind,
    ) -> tuple[Analyzer, ...]:
        """Return the analyzers that should run on a file of the given kind.

        Currently this only filters in one case: LIBRARY_PY files
        (encountered in deep mode) run only analyzers that opt in via
        the `safe_for_library_scan` class attribute. Every other kind
        runs the full analyzer set.

        This is the policy point where "deep mode is density-only" is
        enforced. Future versions may add per-kind analyzer scoping
        for other contexts; the structure here makes that additive.
        """
        if file_kind is FileKind.LIBRARY_PY:
            return tuple(
                a for a in self._analyzers
                if getattr(a, "safe_for_library_scan", False)
            )
        return self._analyzers

    # ========================================================================
    # Per-file dispatch (parsers + analyzers)
    # ========================================================================

    def _analyze_file(
        self,
        content: bytes,
        file_kind: FileKind,
        context: ScanContext,
        diagnostics: list[str],
    ) -> list[Signal]:
        """Dispatch to the correct parser and run all analyzers.

        Returns the flat list of signals across all analyzers for this
        file. Parser or analyzer failures are recorded in diagnostics
        but do not abort the scan.

        For LIBRARY_PY files, the analyzer set is filtered down to
        analyzers that have opted in via `safe_for_library_scan`.
        """
        analyzers = self._select_analyzers_for_kind(file_kind)
        if not analyzers:
            # Possible if all analyzers opt out of LIBRARY_PY scanning.
            # Not an error; the file simply produces no signals.
            return []
        if file_kind is FileKind.PTH:
            return self._analyze_pth(content, context, diagnostics, analyzers)
        # All other in-scope kinds are Python source files:
        # SETUP_PY, INIT_PY, SITECUSTOMIZE, USERCUSTOMIZE, LIBRARY_PY.
        # ENTRY_POINTS is a separate format and not handled in v0.1.
        if file_kind is FileKind.ENTRY_POINTS:
            diagnostics.append(
                "entry_points.txt analysis not implemented in v0.1: "
                f"{context.internal_path}"
            )
            return []
        return self._analyze_python_source(
            content, context, diagnostics, analyzers,
        )

    def _analyze_python_source(
        self,
        content: bytes,
        context: ScanContext,
        diagnostics: list[str],
        analyzers: tuple[Analyzer, ...],
    ) -> list[Signal]:
        """Parse content as Python source and run the given analyzers on it."""
        parsed = parse_python_source(content, context.internal_path)
        signals: list[Signal] = []
        for analyzer in analyzers:
            try:
                signals.extend(analyzer.analyze_python(parsed))
            except Exception as exc:
                diagnostics.append(
                    f"analyzer {analyzer.name} raised on "
                    f"{context.internal_path}: {exc}"
                )
        return signals

    def _analyze_pth(
        self,
        content: bytes,
        context: ScanContext,
        diagnostics: list[str],
        analyzers: tuple[Analyzer, ...],
    ) -> list[Signal]:
        """Parse content as a .pth file and run analyzers on its exec lines.

        We parse the .pth file with its native parser to get the line
        structure, then for each exec line we reparse it as a Python
        source snippet and run the same Python analyzers on it. This
        means every analyzer that cares about Python source patterns
        automatically applies to .pth exec lines without duplication.
        """
        parsed_pth = parse_pth(content, context.internal_path)
        signals: list[Signal] = []

        for line in parsed_pth.lines:
            if line.kind is not LineKind.EXEC:
                continue
            synthetic_path = f"{context.internal_path}:line{line.line_number}"
            parsed_snippet = parse_python_source(
                line.content.encode("utf-8"),
                synthetic_path,
            )
            if not parsed_snippet.is_parseable:
                diagnostics.append(
                    f"could not parse exec line {line.line_number} of "
                    f"{context.internal_path} as Python"
                )
                continue
            for analyzer in analyzers:
                try:
                    for signal in analyzer.analyze_python(parsed_snippet):
                        signals.append(_remap_signal_location(
                            signal, line.line_number,
                        ))
                except Exception as exc:
                    diagnostics.append(
                        f"analyzer {analyzer.name} raised on exec line "
                        f"{line.line_number} of {context.internal_path}: {exc}"
                    )
        return signals

    # ========================================================================
    # Aggregation: per-file outputs into artifact-level result
    # ========================================================================

    def _scan_artifact_with_enumerator(
            self,
            identity: str,
            artifact_kind: ArtifactKind,
            enumerate_fn,
            extract_entry,
            extract_skipped,
            progress_callback: Callable[[int, int], None] | None = None,
        ) -> ScanResult:
            """Run the full pipeline over the output of an entry enumerator.

            Three phases:
            1. Enumerate the artifact and build FileScanInputs.
            2. Run _scan_one_file over each input. (Today serial; this
                is the line that becomes a process pool later.)
            3. Aggregate per-file outputs into a single ScanResult.

            Each caller provides:
            - enumerate_fn: returns an iterable of items.
            - extract_entry: given an item, return (path, bytes) or None.
            - extract_skipped: given an item, return a SkippedFile or None.
            - progress_callback: optional callable invoked once per file
                in Phase 2, with (completed, total). Receives `total =
                len(inputs)`, i.e. only files that survived Phase 1
                triage. Failures inside the callback are swallowed so a
                broken progress bar can never abort a scan.
            """
            started_at = time.perf_counter()

            # ---- Phase 1: enumerate -------------------------------------------
            try:
                items = list(enumerate_fn())
            except Exception as exc:
                return ScanResult(
                    artifact_identity=identity,
                    artifact_kind=artifact_kind,
                    findings=(),
                    skipped=(),
                    statistics=ScanStatistics(
                        duration_seconds=time.perf_counter() - started_at,
                    ),
                    diagnostics=(f"failed to enumerate {identity}: {exc}",),
                )

            pre_skipped: list[SkippedFile] = []
            inputs: list[FileScanInput] = []
            for item in items:
                skipped = extract_skipped(item)
                if skipped is not None:
                    pre_skipped.append(skipped)
                    continue
                entry = extract_entry(item)
                if entry is None:
                    continue
                internal_path, content = entry
                inputs.append(FileScanInput(
                    content=content,
                    internal_path=internal_path,
                    artifact_kind=artifact_kind,
                    artifact_identity=identity,
                    forced_file_kind=None,
                ))

            # ---- Phase 2: per-file scans --------------------------------------
            # When parallelism lands, the loop body becomes:
            #   futures = [executor.submit(self._scan_one_file, inp) for inp in inputs]
            #   for i, future in enumerate(as_completed(futures), start=1):
            #       outputs.append(future.result())
            #       _safe_progress(progress_callback, i, total)
            # The progress_callback contract still works under that shape.
            total = len(inputs)
            outputs: list[FileScanOutput] = []
            for i, inp in enumerate(inputs, start=1):
                outputs.append(self._scan_one_file(inp))
                _safe_progress(progress_callback, i, total)

            # ---- Phase 3: aggregate -------------------------------------------
            return self._aggregate_outputs(
                identity=identity,
                artifact_kind=artifact_kind,
                outputs=outputs,
                pre_skipped=tuple(pre_skipped),
                started_at=started_at,
            )

    def _aggregate_outputs(
        self,
        identity: str,
        artifact_kind: ArtifactKind,
        outputs: list[FileScanOutput],
        pre_skipped: tuple[SkippedFile, ...],
        started_at: float,
    ) -> ScanResult:
        """Combine per-file outputs into an artifact-level ScanResult.

        Pre-enumeration skips (e.g. unsafe paths in a wheel that the
        wheel parser refused to extract) are passed in separately
        because they never went through `_scan_one_file`.
        """
        all_findings: list[Finding] = []
        all_skipped: list[SkippedFile] = list(pre_skipped)
        all_diagnostics: list[str] = []
        all_suppressed: list[SuppressedFinding] = []
        per_file_stats: list[FileStatsEntry] = []

        # Pre-enumeration skips contribute to total and skipped counts
        # but never produced FileScanOutputs, so they need explicit
        # accounting.
        combined = ScanStatistics(
            files_total=len(pre_skipped),
            files_skipped=len(pre_skipped),
        )

        for output in outputs:
            all_findings.extend(output.findings)
            all_skipped.extend(output.skipped)
            all_diagnostics.extend(output.diagnostics)
            all_suppressed.extend(output.suppressed_findings)

            combined.files_total += output.statistics.files_total
            combined.files_scanned += output.statistics.files_scanned
            combined.files_skipped += output.statistics.files_skipped
            combined.signals_emitted += output.statistics.signals_emitted

            per_file_stats.append(FileStatsEntry(
                internal_path=output.internal_path,
                duration_seconds=output.statistics.duration_seconds,
                signals_emitted=output.statistics.signals_emitted,
                findings_count=len(output.findings),
            ))

        combined.analyzers_run = len(self._analyzers)
        combined.duration_seconds = time.perf_counter() - started_at

        return ScanResult(
            artifact_identity=identity,
            artifact_kind=artifact_kind,
            findings=tuple(all_findings),
            skipped=tuple(all_skipped),
            statistics=combined,
            diagnostics=tuple(all_diagnostics),
            suppressed_findings=tuple(all_suppressed),
            per_file_statistics=tuple(per_file_stats),
        )

    def _wrap_single_output_as_result(
        self,
        identity: str,
        artifact_kind: ArtifactKind,
        output: FileScanOutput,
    ) -> ScanResult:
        """Wrap a single FileScanOutput as a ScanResult.

        Used by scan_bytes and scan_loose_file_as. Per-file statistics
        are intentionally NOT populated for single-file scans because
        the data would be redundant with `result.statistics` and
        `result.findings` for one entry.
        """
        return ScanResult(
            artifact_identity=identity,
            artifact_kind=artifact_kind,
            findings=output.findings,
            skipped=output.skipped,
            statistics=output.statistics,
            diagnostics=output.diagnostics,
            suppressed_findings=output.suppressed_findings,
        )


def _remap_signal_location(signal: Signal, base_line: int):
    """Return a new Signal with line position shifted to the outer file.

    Analyzers running on a one-line snippet will report line 1. When
    that snippet came from line N of a .pth file, callers need the
    reported line to be N, not 1. This helper produces a new frozen
    Signal with the adjusted location.
    """
    new_location = SourceLocation(
        line=base_line,
        column=signal.location.column,
    )
    return replace(signal, location=new_location)

def _safe_progress(
    callback: Callable[[int, int], None] | None,
    completed: int,
    total: int,
) -> None:
    """Invoke a progress callback, swallowing any exception.

    The progress callback is a UX nicety, not a correctness
    requirement. A buggy bar must never be allowed to abort a scan.
    Errors are silently dropped here; the user might see a glitchy
    bar but the scan completes.
    """
    if callback is None:
        return
    try:
        callback(completed, total)
    except Exception:
        # Intentionally broad: anything from the callback is a UX
        # problem, not a scan problem. Swallow and continue.
        pass