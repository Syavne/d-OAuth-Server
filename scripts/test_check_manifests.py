#!/usr/bin/env python3
"""Negative fixture tests for scripts/check_manifests.py (plan task 22).

Runs the real lint over the shipped `deploy/k8s` manifests, mutated in memory
for each case, and asserts the exact outcome each case must produce. No live
cluster and no test framework: run with `python3 scripts/test_check_manifests.py`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
MANIFEST_DIR = REPO / "deploy" / "k8s"
CHECKER_PATH = REPO / "scripts" / "check_manifests.py"


def _load_checker():
  spec = importlib.util.spec_from_file_location("check_manifests", CHECKER_PATH)
  if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


CM = _load_checker()


def _load_docs() -> list[dict]:
  docs: list[dict] = []
  for path in sorted(MANIFEST_DIR.glob("*.yaml")):
    if path.name.endswith(".example.yaml"):
      continue
    for doc in yaml.safe_load_all(path.read_text()):
      if doc:
        doc["_source"] = path.name
        docs.append(doc)
  return docs


def _run(docs: list[dict]) -> tuple[int, str]:
  by_source: dict[str, list[dict]] = {}
  for doc in docs:
    clean = {k: v for k, v in doc.items() if not k.startswith("_")}
    by_source.setdefault(doc["_source"], []).append(clean)
  with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    for source, source_docs in by_source.items():
      (tmp_path / source).write_text(yaml.safe_dump_all(source_docs))
    stdout = io.StringIO()
    argv = sys.argv
    sys.argv = ["check_manifests.py", "--manifest-dir", str(tmp_path)]
    try:
      with contextlib.redirect_stdout(stdout):
        code = CM.main()
    finally:
      sys.argv = argv
    return code, stdout.getvalue()


def _template(docs: list[dict]) -> dict:
  deployment = next(d for d in docs if d.get("kind") == "Deployment")
  return deployment["spec"]["template"]["spec"]


def _configmap(docs: list[dict]) -> dict:
  return next(d for d in docs if d.get("kind") == "ConfigMap")


def _secret_volume(tpl: dict) -> dict:
  return next(
    v
    for v in tpl["volumes"]
    if (v.get("secret") or {}).get("secretName") == CM.SECRET_NAME
  )


def test_baseline_manifests_pass():
  code, out = _run(_load_docs())
  assert code == 0, out
  assert "OK" in out


def test_missing_mandatory_pii_projection_fails():
  docs = _load_docs()
  volume = _secret_volume(_template(docs))
  volume["secret"]["items"] = [
    item for item in volume["secret"]["items"] if item["key"] != "pii-encryption-key"
  ]
  code, out = _run(docs)
  assert code == 1, out
  assert "must project key 'pii-encryption-key'" in out, out


def test_inline_pii_secret_env_fails():
  for name in (
    "D_OAUTH_PII_ENCRYPTION_KEY",
    "D_OAUTH_PII_PREVIOUS_KEY",
    "D_OAUTH_TOTP_PREVIOUS_KEY",
  ):
    docs = _load_docs()
    _template(docs)["containers"][0]["env"].append(
      {"name": name, "value": "literal-not-a-file"}
    )
    code, out = _run(docs)
    assert code == 1, (name, out)
    assert f"{name} must not be injected as an env value" in out, (name, out)


def test_configmap_bare_pii_or_previous_key_fails():
  for key in ("pii_encryption_key", "pii_previous_key", "totp_previous_key"):
    docs = _load_docs()
    _configmap(docs)["data"][key] = "bare-secret-value"
    code, out = _run(docs)
    assert code == 1, (key, out)
    assert f"secret-shaped key {key!r}" in out, (key, out)


def test_configmap_nonsecret_pii_settings_are_allowed():
  docs = _load_docs()
  data = _configmap(docs)["data"]
  data["D_OAUTH_PII_DUAL_WRITE"] = "false"
  data["D_OAUTH_PII_KEY_ID"] = "pii-v1"
  data["D_OAUTH_PII_PREVIOUS_KEY_ID"] = "pii-v0"
  data["D_OAUTH_TOTP_PREVIOUS_KEY_ID"] = "totp-v0"
  code, out = _run(docs)
  assert code == 0, out
  assert "OK" in out


def test_previous_key_file_mounted_passes():
  docs = _load_docs()
  tpl = _template(docs)
  tpl["containers"][0]["env"].append(
    {"name": "D_OAUTH_PII_PREVIOUS_KEY_FILE", "value": "/run/secrets/pii-previous-key"}
  )
  _secret_volume(tpl)["secret"]["items"].append(
    {"key": "pii-previous-key", "path": "pii-previous-key"}
  )
  code, out = _run(docs)
  assert code == 0, out
  assert "OK" in out


def test_previous_key_file_literal_value_fails():
  docs = _load_docs()
  _template(docs)["containers"][0]["env"].append(
    {"name": "D_OAUTH_TOTP_PREVIOUS_KEY_FILE", "value": "literal-value"}
  )
  code, out = _run(docs)
  assert code == 1, out
  assert (
    "D_OAUTH_TOTP_PREVIOUS_KEY_FILE must point at /run/secrets/<basename>" in out
  ), out


def test_previous_key_file_unprojected_basename_fails():
  docs = _load_docs()
  _template(docs)["containers"][0]["env"].append(
    {"name": "D_OAUTH_PII_PREVIOUS_KEY_FILE", "value": "/run/secrets/pii-previous-key"}
  )
  code, out = _run(docs)
  assert code == 1, out
  assert "does not project 'pii-previous-key'" in out, out


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
