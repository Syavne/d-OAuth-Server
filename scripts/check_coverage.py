#!/usr/bin/env python3
"""Line-coverage floor checker for d-OAuth-Server.

Reads an lcov tracefile produced by `cargo llvm-cov ... --lcov`, normalizes
every `SF:` path to a workspace-relative path, applies the single canonical
exclusion regex shared with CI, and enforces the floors in
`scripts/coverage_floors.json` (optionally overridden on the command line).

Usage:
  python3 scripts/check_coverage.py lcov.info
  python3 scripts/check_coverage.py lcov.info --floors scripts/coverage_floors.json
  python3 scripts/check_coverage.py lcov.info --global-floor 81.0 \\
      --security-floor 88.0 --module-floor crypto=90.0

The `security` aggregate is exactly the ten core modules: crypto, jose,
protocol, db, store, state, middleware, keys, error, routes. `ui`, `config`,
and `tls` carry per-module floors only and are excluded from the aggregate.

Exit code 0 only when the global line percentage, the security aggregate, and
every listed module meet their floors. A listed module that is missing from the
tracefile, or that contains zero executable lines, fails closed.

Known limitation: inline `#[cfg(test)]` modules inside *production* files cannot
be excluded by filename, so an `--all-targets` run records their lines and
therefore modestly inflates production coverage. The per-module table makes the
effect visible; it does not hide it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLOORS = REPO_ROOT / "scripts" / "coverage_floors.json"

# The ONE canonical exclusion regex. CI passes this same pattern verbatim to
# `cargo llvm-cov --ignore-filename-regex`; keep the two byte-identical.
EXCLUDE_PATTERN = r"(^|/)tests/|(^|/)tests\.rs$|(^|/)tests_[^/]*\.rs$|test_support\.rs$|test_guard\.rs$"
EXCLUDE_RE = re.compile(EXCLUDE_PATTERN)

# Module -> workspace-relative path (directory prefix or exact file). Order is
# the reporting order from the plan and is stable for tests and docs.
MODULE_SPECS = {
  "crypto": "src/crypto/",
  "jose": "src/jose/",
  "protocol": "src/protocol/",
  "db": "src/db/",
  "store": "src/store/",
  "state": "src/state/",
  "middleware": "src/middleware/",
  "ui": "src/ui/",
  "config": "src/config/",
  "keys": "src/keys.rs",
  "error": "src/error.rs",
  "routes": "src/routes.rs",
  "tls": "src/tls.rs",
}
MODULE_ORDER = (
  "crypto",
  "jose",
  "protocol",
  "db",
  "store",
  "state",
  "middleware",
  "ui",
  "config",
  "keys",
  "error",
  "routes",
  "tls",
)
# The ten-module aggregate. ui/config/tls are deliberately absent: they are
# operator-facing/peripheral and carry per-module floors only.
CORE_MODULES = (
  "crypto",
  "jose",
  "protocol",
  "db",
  "store",
  "state",
  "middleware",
  "keys",
  "error",
  "routes",
)


def normalize_sf_path(raw: str, lcov_path: Path) -> str:
  """Return a workspace-relative path for one lcov `SF:` value.

  Handles absolute paths, a leading `./`, paths relative to the workspace
  root, and paths relative to the lcov file's own directory (the common
  "coverage file sits next to the sources" case).
  """
  raw = raw.strip()
  if not raw:
    return raw
  raw_path = Path(raw)
  if raw_path.is_absolute():
    candidates = [raw_path]
  else:
    candidates = [
      REPO_ROOT / raw_path,
      lcov_path.parent / raw_path,
      Path.cwd() / raw_path,
    ]
  repo_root = REPO_ROOT.resolve()
  for candidate in candidates:
    try:
      resolved = candidate.resolve()
    except OSError:
      continue
    try:
      return resolved.relative_to(repo_root).as_posix()
    except ValueError:
      continue
  # Lexical fallback for a path that cannot be placed under the workspace.
  lexical = raw_path.as_posix()
  while lexical.startswith("./"):
    lexical = lexical[2:]
  return lexical


def parse_lcov(text: str) -> list[dict]:
  """Parse lcov `SF:`/`DA:`/`end_of_record` records into source records."""
  records: list[dict] = []
  current: dict | None = None
  for raw_line in text.splitlines():
    line = raw_line.strip()
    if not line:
      continue
    if line.startswith("SF:"):
      if current is not None:
        records.append(current)
      current = {"sf": line[3:], "lines": {}}
    elif line.startswith("DA:"):
      if current is None:
        raise ValueError(f"DA record without a preceding SF record: {line}")
      body = line[3:].split(",")
      if len(body) < 2:
        raise ValueError(f"malformed DA record: {line}")
      try:
        line_no = int(body[0])
        hits = int(body[1])
      except ValueError as exc:
        raise ValueError(f"malformed DA record: {line}") from exc
      previous = current["lines"].get(line_no)
      current["lines"][line_no] = hits if previous is None else max(previous, hits)
    elif line == "end_of_record":
      if current is not None:
        records.append(current)
        current = None
  if current is not None:
    records.append(current)
  return records


def aggregate(records: list[dict], lcov_path: Path) -> dict[str, dict[int, int]]:
  """Merge records into `path -> {line: max hits}`, dropping excluded files."""
  totals: dict[str, dict[int, int]] = {}
  for record in records:
    path = normalize_sf_path(record["sf"], lcov_path)
    if not path or EXCLUDE_RE.search(path):
      continue
    lines = totals.setdefault(path, {})
    for line_no, hits in record["lines"].items():
      previous = lines.get(line_no)
      lines[line_no] = hits if previous is None else max(previous, hits)
  return totals


def line_counts(lines: dict[int, int]) -> tuple[int, int]:
  """Return (executable lines, covered lines) for one file."""
  return len(lines), sum(1 for hits in lines.values() if hits > 0)


def module_of(path: str) -> str | None:
  """Return the listed module a workspace-relative path belongs to, if any."""
  for name in MODULE_ORDER:
    spec = MODULE_SPECS[name]
    if spec.endswith("/"):
      if path.startswith(spec):
        return name
    elif path == spec:
      return name
  return None


def module_counts(totals: dict[str, dict[int, int]]) -> dict[str, dict[str, int]]:
  """Aggregate (`files`, `found`, `hit`) per listed module."""
  counts = {
    name: {"files": 0, "found": 0, "hit": 0}
    for name in MODULE_ORDER
  }
  for path, lines in totals.items():
    name = module_of(path)
    if name is None:
      continue
    found, hit = line_counts(lines)
    counts[name]["files"] += 1
    counts[name]["found"] += found
    counts[name]["hit"] += hit
  return counts


def percent(hit: int, found: int) -> float:
  if found == 0:
    return 0.0
  return 100.0 * hit / found


def _number(value: object, label: str) -> float:
  if isinstance(value, bool) or not isinstance(value, (int, float)):
    raise ValueError(f"{label} must be a number")
  return float(value)


def load_floors(path: Path, explicit: bool) -> dict:
  """Load `{"global", "security", "modules"}`; a missing default means zero."""
  floors = {"global": 0.0, "security": 0.0, "modules": {}}
  if not path.exists():
    if explicit:
      raise ValueError(f"--floors file not found: {path}")
    return floors
  try:
    data = json.loads(path.read_text(encoding="utf-8"))
  except (OSError, json.JSONDecodeError) as exc:
    raise ValueError(f"cannot read floors file {path}: {exc}") from exc
  if not isinstance(data, dict):
    raise ValueError(f"floors file {path} must contain a JSON object")
  if "global" in data:
    floors["global"] = _number(data["global"], "global floor")
  if "security" in data:
    floors["security"] = _number(data["security"], "security floor")
  modules = data.get("modules", {})
  if not isinstance(modules, dict):
    raise ValueError(f"floors file {path}: 'modules' must be an object")
  for name, value in modules.items():
    if name not in MODULE_SPECS:
      raise ValueError(f"floors file {path}: unknown module {name!r}")
    floors["modules"][name] = _number(value, f"module floor {name!r}")
  return floors


def parse_module_overrides(values: list[str]) -> dict[str, float]:
  overrides: dict[str, float] = {}
  for item in values:
    name, sep, raw = item.partition("=")
    if not sep or not name:
      raise ValueError(f"--module-floor expects NAME=F, got {item!r}")
    if name not in MODULE_SPECS:
      raise ValueError(f"--module-floor: unknown module {name!r}")
    try:
      overrides[name] = float(raw)
    except ValueError as exc:
      raise ValueError(f"--module-floor {name}: not a number: {raw!r}") from exc
  return overrides


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    description="Enforce line-coverage floors over an lcov tracefile."
  )
  parser.add_argument("lcov", help="path to an lcov .info tracefile")
  parser.add_argument(
    "--floors",
    default=None,
    help=f"floors JSON (default: {DEFAULT_FLOORS})",
  )
  parser.add_argument(
    "--global-floor",
    type=float,
    default=None,
    help="override the global line-coverage floor (percent)",
  )
  parser.add_argument(
    "--security-floor",
    type=float,
    default=None,
    help="override the security aggregate floor (percent)",
  )
  parser.add_argument(
    "--module-floor",
    action="append",
    default=[],
    metavar="NAME=F",
    help="override one module floor (repeatable)",
  )
  return parser


def main(argv: list[str] | None = None) -> int:
  args = build_parser().parse_args(argv)
  lcov_path = Path(args.lcov)
  floors_path = Path(args.floors) if args.floors else DEFAULT_FLOORS

  try:
    floors = load_floors(floors_path, explicit=args.floors is not None)
    if args.global_floor is not None:
      floors["global"] = float(args.global_floor)
    if args.security_floor is not None:
      floors["security"] = float(args.security_floor)
    floors["modules"].update(parse_module_overrides(args.module_floor))
  except ValueError as exc:
    print(f"coverage check: {exc}")
    return 1

  if not lcov_path.is_file():
    print(f"coverage check: lcov file not found: {lcov_path}")
    return 1
  try:
    records = parse_lcov(lcov_path.read_text(encoding="utf-8"))
  except (OSError, ValueError) as exc:
    print(f"coverage check: cannot parse {lcov_path}: {exc}")
    return 1

  totals = aggregate(records, lcov_path)
  counts = module_counts(totals)
  failures: list[str] = []

  global_found = sum(len(lines) for lines in totals.values())
  global_hit = sum(line_counts(lines)[1] for lines in totals.values())
  global_pct = percent(global_hit, global_found)
  global_floor = floors["global"]
  if global_pct < global_floor:
    failures.append("global below floor")
    global_status = "FAIL: global below floor"
  else:
    global_status = "OK"

  security_found = sum(counts[name]["found"] for name in CORE_MODULES)
  security_hit = sum(counts[name]["hit"] for name in CORE_MODULES)
  security_pct = percent(security_hit, security_found)
  security_floor = floors["security"]
  if security_found == 0:
    failures.append("security aggregate has zero executable lines (fail closed)")
    security_status = "FAIL: zero executable lines (fail closed)"
  elif security_pct < security_floor:
    failures.append("security below floor")
    security_status = "FAIL: security below floor"
  else:
    security_status = "OK"

  print(f"coverage check: {lcov_path}")
  print(
    f"global: {global_pct:.1f}% ({global_hit}/{global_found} lines), "
    f"floor {global_floor:.1f}% -> {global_status}"
  )
  print(
    f"security: {security_pct:.1f}% ({security_hit}/{security_found} lines), "
    f"floor {security_floor:.1f}% -> {security_status}"
  )
  print("per-module line coverage:")
  for name in MODULE_ORDER:
    stats = counts[name]
    pct = percent(stats["hit"], stats["found"])
    floor = floors["modules"].get(name, 0.0)
    if stats["files"] == 0:
      status = "FAIL: missing from lcov (fail closed)"
      failures.append(f"module '{name}' missing from lcov (fail closed)")
    elif stats["found"] == 0:
      status = "FAIL: zero executable lines (fail closed)"
      failures.append(f"module '{name}' has zero executable lines (fail closed)")
    elif pct < floor:
      status = f"FAIL: below floor ({floor:.1f}%)"
      failures.append(f"module '{name}' below floor: {pct:.1f}% < {floor:.1f}%")
    else:
      status = "OK"
    scope = "" if name in CORE_MODULES else "  (per-module only)"
    print(
      f"  {name:<10} {pct:>6.1f}% ({stats['hit']}/{stats['found']} lines) "
      f"floor {floor:>5.1f}%  {status}{scope}"
    )

  if failures:
    print("failed checks:")
    for failure in failures:
      print(f"  - {failure}")
    print(f"RESULT: FAIL ({len(failures)} check(s))")
    return 1
  print("RESULT: PASS")
  return 0


if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
