#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    print(f"[FAIL] {message}", file=sys.stderr)
    raise SystemExit(1)


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def ok(message: str) -> None:
    print(f"[OK] {message}")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rows.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                fail(f"{path} line {line_number} is not valid JSON: {exc}")
    return rows


def assert_forbidden_keys_absent(
    obj: Any, forbidden: set[str], path: str = "$"
) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in forbidden:
                fail(f"forbidden payload-bearing key leaked at {path}.{key}")
            assert_forbidden_keys_absent(value, forbidden, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for index, item in enumerate(obj):
            assert_forbidden_keys_absent(item, forbidden, f"{path}[{index}]")


def get_summary_count(
    summary: dict[str, Any], name: str, fallback: int | None = None
) -> int | None:
    value = summary.get(name)
    if isinstance(value, int):
        return value
    return fallback


def expect_attr_blocked(result: Any, name: str) -> None:
    try:
        getattr(result, name)
    except Exception:
        ok(f"public result blocks result.{name}")
        return
    fail(f"public result unexpectedly exposes result.{name}")


def assert_event_sequence(events: list[dict[str, Any]]) -> None:
    event_types = [event.get("event_type") for event in events]

    required = [
        "internal.scanner.scan_grant_issued",
        "internal.scanner.engine_created",
        "internal.scanner.scan_started",
        "internal.scanner.scan_completed",
        "internal.scanner.decode_started",
        "internal.scanner.decode_completed",
        "internal.scanner.run_completed",
    ]

    missing = [event_type for event_type in required if event_type not in event_types]
    if missing:
        fail(f"event log is missing required events: {missing}")

    positions = [event_types.index(event_type) for event_type in required]
    if positions != sorted(positions):
        fail(f"event order is wrong: {event_types}")

    ok("event sequence is present and ordered")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smoke-test pydepgate.api against a known bad local wheel."
    )
    parser.add_argument("wheel", help="Path to a known bad .whl file")
    parser.add_argument(
        "--out-dir",
        default="api_smoke_out",
        help="Directory for generated reports and event logs",
    )
    parser.add_argument("--expect-findings", type=int, default=None)
    parser.add_argument("--expect-diagnostics", type=int, default=None)
    parser.add_argument("--expect-iocs", type=int, default=None)
    parser.add_argument(
        "--test-full-archive",
        action="store_true",
        help="Also run decode_iocs=full and test unsafe payload archive export",
    )
    args = parser.parse_args()

    wheel = Path(args.wheel)
    if not wheel.exists():
        fail(f"wheel does not exist: {wheel}")
    if wheel.suffix.lower() != ".whl":
        fail(f"target must be a .whl file for this smoke test: {wheel}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        import pydepgate.api as pydepgate
    except Exception:
        traceback.print_exc()
        fail("could not import pydepgate.api")

    print(f"[INFO] pydepgate.api module: {pydepgate.__file__}")
    print(f"[INFO] target wheel: {wheel}")
    print(f"[INFO] output dir: {out_dir}")

    api_error_type = getattr(pydepgate, "PyDepGateApiError", Exception)

    # Guardrail test: this should be impossible.
    try:
        pydepgate.scan(str(wheel), mode="static", single=True)
    except api_error_type:
        ok("single=True is blocked for .whl targets")
    except Exception as exc:
        fail(
            f"single=True raised the wrong exception type: {type(exc).__name__}: {exc}"
        )
    else:
        fail("single=True was allowed for a .whl target")

    event_log = out_dir / "events.jsonl"

    result = pydepgate.scan(
        str(wheel),
        mode="static",
        single=False,
        deep=True,
        peek=True,
        peek_chain=True,
        decode=True,
        decode_payload_depth=5,
        decode_iocs="hashes",
        event_log=str(event_log),
        min_severity="high",
        output_format="text",
    )

    print(f"[INFO] result repr: {result!r}")

    summary = result.to_summary()
    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    ok(f"wrote summary: {summary_path}")

    finding_count = getattr(result, "finding_count", None)
    diagnostic_count = getattr(result, "diagnostic_count", None)
    iocs = tuple(getattr(result, "iocs", ()))

    print(f"[INFO] finding_count: {finding_count}")
    print(f"[INFO] diagnostic_count: {diagnostic_count}")
    print(f"[INFO] ioc_count: {len(iocs)}")

    if args.expect_findings is not None and finding_count != args.expect_findings:
        fail(f"expected {args.expect_findings} findings, got {finding_count}")

    if (
        args.expect_diagnostics is not None
        and diagnostic_count != args.expect_diagnostics
    ):
        fail(f"expected {args.expect_diagnostics} diagnostics, got {diagnostic_count}")

    if args.expect_iocs is not None and len(iocs) != args.expect_iocs:
        fail(f"expected {args.expect_iocs} IOCs, got {len(iocs)}")

    if finding_count is None or finding_count <= 0:
        fail("scan returned no findings")

    if not event_log.exists():
        fail(f"event log was not written: {event_log}")

    events = load_jsonl(event_log)
    ok(f"event log has {len(events)} events")
    assert_event_sequence(events)

    scan_completed = next(
        event
        for event in events
        if event.get("event_type") == "internal.scanner.scan_completed"
    )
    scan_payload = scan_completed.get("payload", {})
    if scan_payload.get("artifact_kind") != "wheel":
        fail(
            f"scan_completed artifact_kind is not wheel: {scan_payload.get('artifact_kind')!r}"
        )
    if scan_payload.get("finding_count") != finding_count:
        fail(
            "event finding_count does not match result finding_count: "
            f"{scan_payload.get('finding_count')} != {finding_count}"
        )
    ok("scan_completed matches public result count")

    decode_completed = next(
        event
        for event in events
        if event.get("event_type") == "internal.scanner.decode_completed"
    )
    decode_payload = decode_completed.get("payload", {})
    if not decode_payload.get("tree_available"):
        fail("decode_completed says no decoded tree was available")
    if "ioc_count" not in decode_payload:
        fail("decode_completed payload does not include ioc_count")
    ok("decode_completed includes decoded-tree and IOC summary")

    # Safe findings should preserve limited peek/peek-chain data but not full payload material.
    findings = tuple(getattr(result, "findings", ()))
    if not findings:
        fail("result.findings is empty")

    decoded_preview_count = 0
    for finding in findings:
        context = getattr(finding, "context", {})
        assert_forbidden_keys_absent(
            context,
            forbidden={"_full_value", "_full_value_truncated", "der_full"},
        )
        decoded = context.get("decoded") if isinstance(context, dict) else None
        if isinstance(decoded, dict):
            decoded_preview_count += 1
            assert_forbidden_keys_absent(
                decoded,
                forbidden={
                    "_full_value",
                    "_full_value_truncated",
                    "decoded_source",
                    "raw_payload",
                },
            )

    if decoded_preview_count == 0:
        warn("no safe decoded preview blocks found in result.findings")
    else:
        ok(f"safe decoded preview blocks found: {decoded_preview_count}")

    # Public unsafe surfaces should be blocked by default.
    for attr_name in ("result", "outcome", "decoded_tree"):
        expect_attr_blocked(result, attr_name)

    # Explicit unsafe native access should work with the capability token.
    native = result.get_native_result(unsafe=pydepgate.UNSAFE.ALLOW_NATIVE_RESULT)
    if not getattr(native, "findings", None):
        fail("unsafe native result access worked, but native result had no findings")
    ok("unsafe native result access requires token and works")

    # In hashes mode, decoded tree access may exist with a token, but it should not retain decoded_source.
    tree = result.get_decoded_tree(unsafe=pydepgate.UNSAFE.ALLOW_DECODED_TREE)
    tree_repr = repr(tree)
    if "decoded_source=" in tree_repr and "decoded_source=None" not in tree_repr:
        fail("decode_iocs='hashes' appears to retain decoded_source in decoded tree")
    ok("decode_iocs='hashes' does not expose decoded_source in decoded tree repr")

    # Renderers should use the existing reporter stack.
    report_txt = out_dir / "report.txt"
    report_json = out_dir / "report.json"
    report_sarif = out_dir / "report.sarif.json"
    ioc_txt = out_dir / "iocs.txt"

    result.write_report(report_txt, format="text")
    result.write_report(report_json, format="json")
    result.write_report(report_sarif, format="sarif")
    result.write_iocs(ioc_txt)

    for path in (report_txt, report_json, report_sarif, ioc_txt):
        if not path.exists() or path.stat().st_size == 0:
            fail(f"expected non-empty output file: {path}")
        ok(f"wrote {path} ({path.stat().st_size} bytes)")

    try:
        json.loads(report_json.read_text(encoding="utf-8"))
        ok("JSON report parses")
    except Exception as exc:
        fail(f"JSON report did not parse: {exc}")

    try:
        sarif_obj = json.loads(report_sarif.read_text(encoding="utf-8"))
        if sarif_obj.get("version") != "2.1.0":
            fail(f"SARIF report has unexpected version: {sarif_obj.get('version')!r}")
        ok("SARIF report parses")
    except Exception as exc:
        fail(f"SARIF report did not parse: {exc}")

    # Payload archive should not be allowed from hashes mode.
    try:
        result.write_payload_archive(
            out_dir / "payloads_should_not_exist.zip",
            unsafe=pydepgate.UNSAFE.ALLOW_PAYLOAD_ARCHIVE_EXPORT,
        )
    except Exception:
        ok("payload archive export is blocked unless decode_iocs='full'")
    else:
        fail("payload archive export unexpectedly worked in decode_iocs='hashes' mode")

    if args.test_full_archive:
        print(
            "[INFO] running second scan with decode_iocs='full' for unsafe archive export"
        )
        full_result = pydepgate.scan(
            str(wheel),
            mode="static",
            single=False,
            deep=True,
            peek=True,
            peek_chain=True,
            decode=True,
            decode_payload_depth=5,
            decode_iocs="full",
            event_log=str(out_dir / "events_full.jsonl"),
            min_severity="high",
            output_format="text",
        )
        archive_path = out_dir / "payloads.zip"
        full_result.write_payload_archive(
            archive_path,
            unsafe=pydepgate.UNSAFE.ALLOW_PAYLOAD_ARCHIVE_EXPORT,
        )
        if not archive_path.exists() or archive_path.stat().st_size == 0:
            fail("unsafe payload archive was requested but not written")
        ok(f"unsafe payload archive written: {archive_path}")

    print("[PASS] API smoke test completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
