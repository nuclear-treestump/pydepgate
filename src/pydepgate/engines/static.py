"""
Static analysis engine.

Given an artifact (a loose file for v0.1; wheels and sdists in the
next unit), the static engine:

  1. Enumerates files within the artifact.
  2. Asks the triage module which files are in scope.
  3. For each in-scope file, invokes the appropriate parser.
  4. Runs each registered analyzer against the parsed representation.
  5. Converts signals to findings using the v0.1 confidence mapping.
  6. Returns a ScanResult.

The engine is deliberately simple. All intelligence lives in the
parsers, analyzers, and (eventually) rules. The engine is just glue.
"""

from __future__ import annotations

import time
from pathlib import Path

from pydepgate.analyzers.base import Analyzer, Signal
from pydepgate.engines.base import (
    ArtifactKind,
    Finding,
    ScanContext,
    ScanResult,
    ScanStatistics,
    SkippedFile,
    confidence_to_severity_v01,
)
from pydepgate.parsers.pth import parse_pth, LineKind
from pydepgate.parsers.pysource import parse_python_source
from pydepgate.traffic_control.triage import FileKind, triage


class StaticEngine:
    """Static analysis engine for pydepgate artifacts.

    The engine is stateless across scans: you can reuse a single
    instance for many scan calls. Analyzers are passed in at
    construction time.

    In v0.1, the list of analyzers is explicit. A decorator-based
    registry can layer on top later without changing this interface:
    a helper like `StaticEngine.with_registered_analyzers()` would
    build the list from a module-level registry and pass it to
    __init__ unchanged.
    """

    def __init__(self, analyzers: list[Analyzer]) -> None:
        self._analyzers: tuple[Analyzer, ...] = tuple(analyzers)

    @property
    def analyzers(self) -> tuple[Analyzer, ...]:
        """The analyzers configured for this engine, in registration order."""
        return self._analyzers

    def scan_file(self, path: Path) -> ScanResult:
        """Scan a single loose file on disk.

        Uses the filename to let triage determine the file's kind,
        then routes to the appropriate parser and analyzer set.
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

        This is the primary entry point used internally by other scan
        methods. When wheel and sdist support is added, those methods
        call scan_bytes once per in-scope file and aggregate results.

        Args:
            content: The file's raw bytes.
            internal_path: The file's path within its artifact. Used
                by triage to decide scope.
            artifact_kind: What kind of outer artifact this came from.
            artifact_identity: Identifier for the outer artifact. If
                None, the internal_path is used.

        Returns:
            A ScanResult containing findings (possibly empty) for
            this file.
        """
        identity = artifact_identity or internal_path
        stats = ScanStatistics(files_total=1)
        findings: list[Finding] = []
        skipped: list[SkippedFile] = []
        diagnostics: list[str] = []

        started_at = time.perf_counter()

        decision = triage(internal_path)

        if decision.kind is FileKind.SKIP:
            stats.files_skipped = 1
            skipped.append(SkippedFile(
                internal_path=decision.internal_path,
                reason=decision.reason,
            ))
            stats.duration_seconds = time.perf_counter() - started_at
            return ScanResult(
                artifact_identity=identity,
                artifact_kind=artifact_kind,
                findings=(),
                skipped=tuple(skipped),
                statistics=stats,
                diagnostics=tuple(diagnostics),
            )

        context = ScanContext(
            artifact_kind=artifact_kind,
            artifact_identity=identity,
            internal_path=decision.internal_path,
            file_kind=decision.kind,
            triage_reason=decision.reason,
        )

        signals = self._analyze_file(content, decision.kind, context, diagnostics)
        stats.files_scanned = 1
        stats.signals_emitted = len(signals)
        stats.analyzers_run = len(self._analyzers)

        for signal in signals:
            findings.append(Finding(
                signal=signal,
                severity=confidence_to_severity_v01(signal.confidence),
                context=context,
            ))

        stats.duration_seconds = time.perf_counter() - started_at
        return ScanResult(
            artifact_identity=identity,
            artifact_kind=artifact_kind,
            findings=tuple(findings),
            skipped=tuple(skipped),
            statistics=stats,
            diagnostics=tuple(diagnostics),
        )

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
        """
        if file_kind is FileKind.PTH:
            return self._analyze_pth(content, context, diagnostics)
        # All other in-scope kinds are Python source files:
        # SETUP_PY, INIT_PY, SITECUSTOMIZE, USERCUSTOMIZE.
        # ENTRY_POINTS is a separate format and not handled in v0.1.
        if file_kind is FileKind.ENTRY_POINTS:
            diagnostics.append(
                f"entry_points.txt analysis not implemented in v0.1: {context.internal_path}"
            )
            return []
        return self._analyze_python_source(content, context, diagnostics)

    def _analyze_python_source(
        self,
        content: bytes,
        context: ScanContext,
        diagnostics: list[str],
    ) -> list[Signal]:
        """Parse content as Python source and run all analyzers on it."""
        parsed = parse_python_source(content, context.internal_path)
        signals: list[Signal] = []
        for analyzer in self._analyzers:
            try:
                signals.extend(analyzer.analyze_python(parsed))
            except Exception as exc:
                diagnostics.append(
                    f"analyzer {analyzer.name} raised on {context.internal_path}: {exc}"
                )
        return signals

    def _analyze_pth(
        self,
        content: bytes,
        context: ScanContext,
        diagnostics: list[str],
    ) -> list[Signal]:
        """Parse content as a .pth file and run analyzers on its exec lines.

        Per the design decision (Option A): we parse the .pth file
        with its native parser to get the line structure, then for
        each exec line we reparse it as a Python source snippet and
        run the same Python analyzers on it. This means every analyzer
        that cares about Python source patterns automatically applies
        to .pth exec lines without duplication.
        """
        parsed_pth = parse_pth(content, context.internal_path)
        signals: list[Signal] = []

        for line in parsed_pth.lines:
            if line.kind is not LineKind.EXEC:
                continue
            # Wrap this single exec line as a Python module so the
            # source-level analyzers can see it. The synthetic path
            # includes the line number so analyzer-reported locations
            # can be mapped back to the .pth file.
            synthetic_path = f"{context.internal_path}:line{line.line_number}"
            parsed_snippet = parse_python_source(
                line.content.encode("utf-8"),
                synthetic_path,
            )
            if not parsed_snippet.is_parseable:
                # Unparseable exec lines in a .pth file are themselves
                # unusual and worth noting, but that is an analyzer's
                # job, not the engine's.
                diagnostics.append(
                    f"could not parse exec line {line.line_number} of "
                    f"{context.internal_path} as Python"
                )
                continue
            for analyzer in self._analyzers:
                try:
                    # Re-emit signals with their location adjusted to
                    # the .pth file coordinate system. The analyzer
                    # reports line 1 within the snippet; we remap to
                    # the actual line number in the .pth file.
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


def _remap_signal_location(signal: Signal, base_line: int):
    """Return a new Signal with line position shifted to the outer file.

    Analyzers running on a one-line snippet will report line 1. When
    that snippet came from line N of a .pth file, callers need the
    reported line to be N, not 1. This helper produces a new frozen
    Signal with the adjusted location.
    """
    from dataclasses import replace
    from pydepgate.parsers.pysource import SourceLocation
    new_location = SourceLocation(
        line=base_line,
        column=signal.location.column,
    )
    return replace(signal, location=new_location)