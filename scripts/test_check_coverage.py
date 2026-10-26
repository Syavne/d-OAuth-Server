#!/usr/bin/env python3
"""Fixture tests for scripts/check_coverage.py (plan todo 1).

Every case builds an lcov tracefile in a fresh temporary directory, runs the
real checker over it, and asserts the exit code and the message the contract
requires. No network, no framework: `python3 scripts/test_check_coverage.py`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHECKER_PATH = REPO / "scripts" / "check_coverage.py"

# Independent copy of the canonical regex: if the checker's constant drifts
# from the one CI uses, this literal stops matching and the test fails.
CANONICAL_EXCLUDE = r"(^|/)tests/|(^|/)tests\.rs$|(^|/)tests_[^/]*\.rs$|test_support\.rs$|test_guard\.rs$"


def _load_checker():
  spec = importlib.util.spec_from_file_location("check_coverage", CHECKER_PATH)
  if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


CM = _load_checker()


def _module_path(name: str) -> str:
  spec = CM.MODULE_SPECS[name]
  return spec if not spec.endswith("/") else spec + "mod.rs"


def _module_records(names, hits: int, lines: int = 4) -> list:
  return [
    (_module_path(name), [(line_no, hits) for line_no in range(1, lines + 1)])
    for name in names
  ]


def _lcov_text(records: list) -> str:
  out: list[str] = []
  for sf, das in records:
    out.append(f"SF:{sf}")
    for line_no, hits in das:
      out.append(f"DA:{line_no},{hits}")
    out.append("end_of_record")
  return "\n".join(out) + "\n"


def _write_lcov(directory: Path, records: list) -> Path:
  lcov_path = directory / "lcov.info"
  lcov_path.write_text(_lcov_text(records), encoding="utf-8")
  return lcov_path


def _run(records: list, *args: str) -> tuple[int, str]:
  directory = Path(tempfile.mkdtemp(prefix="check-coverage-"))
  try:
    lcov_path = _write_lcov(directory, records)
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
      code = CM.main([str(lcov_path), *args])
    return code, stdout.getvalue()
  finally:
    shutil.rmtree(directory, ignore_errors=True)


def test_full_coverage_passes():
  records = _module_records(CM.MODULE_ORDER, hits=1)
  code, out = _run(
    records,
    "--global-floor",
    "100.0",
    "--security-floor",
    "100.0",
  )
  assert code == 0, out
  assert "RESULT: PASS" in out, out


def test_zero_coverage_fails_below_global_floor():
  records = _module_records(CM.MODULE_ORDER, hits=0)
  code, out = _run(records, "--global-floor", "1.0", "--security-floor", "0.0")
  assert code == 1, out
  assert "global below floor" in out, out


def test_missing_security_group_fails_closed():
  records = _module_records(("ui", "config", "tls"), hits=1)
  code, out = _run(records, "--global-floor", "0.0", "--security-floor", "0.0")
  assert code == 1, out
  assert "security" in out, out
  assert "fail closed" in out, out


def test_tests_e2e_records_are_excluded():
  records = _module_records(CM.MODULE_ORDER, hits=1)
  records.append(("tests/e2e/flow.rs", [(1, 0), (2, 0)]))
  code, out = _run(
    records,
    "--global-floor",
    "100.0",
    "--security-floor",
    "100.0",
  )
  assert code == 0, out
  assert "RESULT: PASS" in out, out


def test_module_test_files_are_excluded():
  records = _module_records(CM.MODULE_ORDER, hits=1)
  records.append(("src/protocol/tests_extra.rs", [(1, 0), (2, 0)]))
  records.append(("src/protocol/tests.rs", [(1, 0)]))
  records.append(("src/test_support.rs", [(1, 0)]))
  records.append(("src/test_guard.rs", [(1, 0)]))
  code, out = _run(
    records,
    "--global-floor",
    "100.0",
    "--security-floor",
    "100.0",
  )
  assert code == 0, out
  assert "RESULT: PASS" in out, out


def test_one_module_below_its_floor_fails():
  records: list = []
  for name in CM.MODULE_ORDER:
    hits = 0 if name == "crypto" else 1
    records.extend(_module_records((name,), hits=hits))
  code, out = _run(
    records,
    "--module-floor",
    "crypto=100.0",
    "--global-floor",
    "0.0",
    "--security-floor",
    "0.0",
  )
  assert code == 1, out
  assert "module 'crypto' below floor" in out, out


def test_canonical_exclude_regex_matches_ci_contract():
  assert CM.EXCLUDE_PATTERN == CANONICAL_EXCLUDE
  assert CM.EXCLUDE_RE.pattern == CANONICAL_EXCLUDE
  for path in (
    "tests/e2e/flow.rs",
    "tests/integration.rs",
    "src/protocol/tests.rs",
    "src/protocol/tests_extra.rs",
    "src/test_support.rs",
    "src/test_guard.rs",
  ):
    assert CM.EXCLUDE_RE.search(path), path
  for path in ("src/protocol/cimd.rs", "src/routes.rs", "src/crypto/hash.rs"):
    assert not CM.EXCLUDE_RE.search(path), path


def test_aggregation_merges_duplicates_and_totals_modules():
  records = [
    ("src/crypto/a.rs", [(1, 1), (2, 0)]),
    ("src/crypto/a.rs", [(1, 3), (3, 1)]),
    ("src/crypto/b.rs", [(1, 0)]),
    ("src/jose/j.rs", [(1, 1)]),
    ("src/other.rs", [(1, 0)]),
    ("tests/e2e/x.rs", [(1, 0)]),
  ]
  directory = Path(tempfile.mkdtemp(prefix="check-coverage-agg-"))
  try:
    lcov_path = _write_lcov(directory, records)
    totals = CM.aggregate(
      CM.parse_lcov(lcov_path.read_text(encoding="utf-8")), lcov_path
    )
  finally:
    shutil.rmtree(directory, ignore_errors=True)

  assert totals["src/crypto/a.rs"] == {1: 3, 2: 0, 3: 1}
  assert totals["src/crypto/b.rs"] == {1: 0}
  assert "tests/e2e/x.rs" not in totals
  counts = CM.module_counts(totals)
  assert counts["crypto"] == {"files": 2, "found": 4, "hit": 2}
  assert counts["jose"] == {"files": 1, "found": 1, "hit": 1}
  global_found = sum(len(lines) for lines in totals.values())
  global_hit = sum(CM.line_counts(lines)[1] for lines in totals.values())
  assert (global_hit, global_found) == (3, 6)
  assert CM.percent(global_hit, global_found) == 50.0


def main() -> int:
  tests = [
    value
    for name, value in sorted(globals().items())
    if name.startswith("test_") and callable(value)
  ]
  failed = 0
  for test in tests:
    try:
      test()
    except AssertionError as exc:
      failed += 1
      print(f"FAIL {test.__name__}: {exc}")
    else:
      print(f"PASS {test.__name__}")
  print(f"{len(tests) - failed}/{len(tests)} passed")
  return 1 if failed else 0


if __name__ == "__main__":
  sys.exit(main())
