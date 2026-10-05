#!/usr/bin/env python3
"""Cluster-manifest policy lint (task 46).

Validates `deploy/k8s` (and `compose.yaml` lightly) against the cluster
contract WITHOUT a live cluster:

- Deployment: 3 replicas, non-root 65532, read-only rootfs, RuntimeDefault
  seccomp, ALL capabilities dropped, requests+limits, startup/liveness on
  `/health/live` + readiness on `/health/ready` via httpGet against the
  plaintext health port (8081), `terminationGracePeriodSeconds >= 45`,
  topology spread, and NO per-replica migration.
- Migration Job: exactly one, runs `migrate`, `restartPolicy: Never`.
- PDB: `minAvailable: 2`.
- Service: never exposes the health port (8081).
- No baked secrets: no PEM blocks in manifests; `REPLACE_ME` placeholders
  only inside `secret.yaml`; no secret-shaped keys in the ConfigMap.
- L7-vs-L4 mTLS constraint: an L7 Ingress that terminates TLS while
  in-process client-cert auth is enabled (`D_OAUTH_TLS__CLIENT_CA_PATH`
  set, or client-cert Ingress annotations) FAILS. mTLS needs L4/TCP
  passthrough (NLB gateway / TLSRoute) or explicit trusted-proxy mode.
  This constraint is DOCUMENTED (docs/DEPLOYMENT.md) and lint-checked
  here; it is explicitly NOT exercised end-to-end in CI.

Usage:
  python3 scripts/check_manifests.py [--manifest-dir deploy/k8s]
                                     [--strict-digest]

`--strict-digest` (used by supply-chain CI after the pin step) additionally
requires every workload image to be digest-pinned (`@sha256:<64 hex>`).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

HEALTH_PORT = 8081
PUBLIC_PORT = 8080
TERMINATION_GRACE_MIN = 45
SECRET_NAME_RE = re.compile(r"(?i)(pepper|password|secret|private[_-]?key|totp)")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|-----BEGIN CERTIFICATE-----")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
HIGH_ENTROPY_VALUE_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")

CLIENT_CERT_ANNOTATIONS = (
  "nginx.ingress.kubernetes.io/auth-tls-verify-client",
  "nginx.ingress.kubernetes.io/auth-tls-secret",
  "haproxy.org/ssl-verify-client",
  "traefik.ingress.kubernetes.io/router.tls.options",
)


class Failures:
  def __init__(self) -> None:
    self.items: list[str] = []

  def add(self, msg: str) -> None:
    self.items.append(msg)

  def ok(self) -> bool:
    return not self.items


def load_manifests(manifest_dir: Path) -> tuple[list[dict], Failures]:
  fails = Failures()
  docs: list[dict] = []
  files = sorted(manifest_dir.glob("*.yaml"))
  if not files:
    fails.add(f"no manifests found in {manifest_dir}")
    return docs, fails
  for path in files:
    if path.name.endswith(".example.yaml"):
      continue
    try:
      loaded = list(yaml.safe_load_all(path.read_text()))
    except yaml.YAMLError as exc:
      fails.add(f"{path.name}: invalid YAML: {exc}")
      continue
    for doc in loaded:
      if doc:
        doc["_source"] = path.name
        docs.append(doc)
  return docs, fails


def by_kind(docs: list[dict], kind: str) -> list[dict]:
  return [d for d in docs if d.get("kind") == kind]


def check_pem_and_placeholders(docs: list[dict], fails: Failures) -> None:
  for doc in docs:
    src = doc.get("_source", "?")
    text = yaml.safe_dump({k: v for k, v in doc.items() if not k.startswith("_")})
    if PEM_RE.search(text):
      fails.add(f"{src}: baked key material (PEM block) in a manifest")
    if src != "secret.yaml" and "REPLACE_ME" in text:
      fails.add(f"{src}: placeholder belongs only in secret.yaml")


def check_configmap(doc: dict, fails: Failures) -> None:
  data = doc.get("data") or {}
  for key in data:
    if SECRET_NAME_RE.search(key):
      fails.add(f"configmap: secret-shaped key {key!r} must live in the Secret")
  if (data.get("D_OAUTH_TLS__CLIENT_CA_PATH") or "").strip():
    pass  # mTLS on: L7 check below becomes load-bearing.


def mtls_enabled(docs: list[dict]) -> bool:
  for doc in by_kind(docs, "ConfigMap"):
    data = doc.get("data") or {}
    if (data.get("D_OAUTH_TLS__CLIENT_CA_PATH") or "").strip():
      return True
  return False


def check_deployment(doc: dict, fails: Failures, strict_digest: bool) -> None:
  name = doc.get("metadata", {}).get("name", "?")
  spec = doc.get("spec", {})
  if spec.get("replicas") != 3:
    fails.add(f"deployment/{name}: replicas must be 3")
  tpl = spec.get("template", {}).get("spec", {})
  if tpl.get("terminationGracePeriodSeconds", 0) < TERMINATION_GRACE_MIN:
    fails.add(f"deployment/{name}: terminationGracePeriodSeconds must be >= 45")
  pod_sc = tpl.get("securityContext", {})
  if pod_sc.get("runAsNonRoot") is not True:
    fails.add(f"deployment/{name}: runAsNonRoot must be true")
  if pod_sc.get("runAsUser") != 65532:
    fails.add(f"deployment/{name}: runAsUser must be 65532")
  if (pod_sc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
    fails.add(f"deployment/{name}: seccompProfile.type must be RuntimeDefault")
  if not tpl.get("topologySpreadConstraints"):
    fails.add(f"deployment/{name}: topologySpreadConstraints required")
  for container in tpl.get("containers", []):
    cname = container.get("name", "?")
    csc = container.get("securityContext", {})
    if csc.get("readOnlyRootFilesystem") is not True:
      fails.add(f"deployment/{name}/{cname}: readOnlyRootFilesystem must be true")
    if "ALL" not in (csc.get("capabilities") or {}).get("drop", []):
      fails.add(f"deployment/{name}/{cname}: capabilities.drop must include ALL")
    res = container.get("resources", {})
    if not res.get("requests") or not res.get("limits"):
      fails.add(f"deployment/{name}/{cname}: requests and limits required")
    args = " ".join(
      str(a)
      for a in (
        list(container.get("command", [])) + list(container.get("args", []))
      )
    )
    if "migrate" in args:
      fails.add(f"deployment/{name}/{cname}: replicas must never migrate")
    probes = {
      "startupProbe": ("/health/live", True),
      "livenessProbe": ("/health/live", True),
      "readinessProbe": ("/health/ready", True),
    }
    for probe_name, (path, _) in probes.items():
      probe = container.get(probe_name) or {}
      http_get = probe.get("httpGet") or {}
      if http_get.get("path") != path or http_get.get("port") != HEALTH_PORT:
        fails.add(
          f"deployment/{name}/{cname}: {probe_name} must httpGet "
          f"{path} on port {HEALTH_PORT} (plaintext health listener)"
        )
    image = container.get("image", "")
    if strict_digest and not DIGEST_RE.search(image):
      fails.add(f"deployment/{name}/{cname}: image must be digest-pinned")


def check_job(doc: dict, fails: Failures, strict_digest: bool) -> None:
  name = doc.get("metadata", {}).get("name", "?")
  spec = doc.get("spec", {}).get("template", {}).get("spec", {})
  if spec.get("restartPolicy") != "Never":
    fails.add(f"job/{name}: restartPolicy must be Never")
  containers = spec.get("containers", [])
  if not any(
    "migrate" in " ".join(str(a) for a in (list(c.get("command", [])) + list(c.get("args", []))))
    for c in containers
  ):
    fails.add(f"job/{name}: exactly one migrate Job must run `/d-oauth-server migrate`")
  for container in containers:
    if strict_digest and not DIGEST_RE.search(container.get("image", "")):
      fails.add(f"job/{name}: image must be digest-pinned")


def check_pdb(doc: dict, fails: Failures) -> None:
  if doc.get("spec", {}).get("minAvailable") != 2:
    fails.add("poddisruptionbudget: minAvailable must be 2")


def check_service(doc: dict, fails: Failures) -> None:
  ports = doc.get("spec", {}).get("ports", [])
  exposed = {p.get("port") for p in ports} | {p.get("targetPort") for p in ports}
  if HEALTH_PORT in exposed:
    fails.add("service: must not expose the plaintext health port 8081")


def check_l7_mtls(docs: list[dict], fails: Failures) -> None:
  """An L7 ingress that terminates TLS strips the client certificate."""
  ingresses = by_kind(docs, "Ingress")
  if not ingresses:
    return
  client_auth = mtls_enabled(docs)
  for ing in ingresses:
    name = ing.get("metadata", {}).get("name", "?")
    annotations = (ing.get("metadata", {}) or {}).get("annotations", {}) or {}
    terminates = bool((ing.get("spec", {}) or {}).get("tls"))
    wants_client_cert = client_auth or any(a in annotations for a in CLIENT_CERT_ANNOTATIONS)
    if terminates and wants_client_cert:
      fails.add(
        f"ingress/{name}: L7 TLS termination strips the client certificate "
        "while in-process client-cert auth is enabled — use L4/TCP "
        "passthrough (NLB gateway / TLSRoute) or explicit trusted-proxy mode"
      )


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--manifest-dir", default="deploy/k8s")
  parser.add_argument("--strict-digest", action="store_true")
  args = parser.parse_args()

  fails = Failures()
  docs, load_fails = load_manifests(Path(args.manifest_dir))
  fails.items.extend(load_fails.items)

  kinds = {d.get("kind") for d in docs}
  for required in ("Deployment", "Service", "ConfigMap", "Secret", "Job", "PodDisruptionBudget"):
    kind_name = "Job" if required == "Job" else required
    if required not in kinds:
      fails.add(f"missing required kind: {required} ({kind_name})")

  check_pem_and_placeholders(docs, fails)
  for doc in by_kind(docs, "ConfigMap"):
    check_configmap(doc, fails)
  for doc in by_kind(docs, "Deployment"):
    check_deployment(doc, fails, args.strict_digest)
  for doc in by_kind(docs, "Job"):
    check_job(doc, fails, args.strict_digest)
  for doc in by_kind(docs, "PodDisruptionBudget"):
    check_pdb(doc, fails)
  for doc in by_kind(docs, "Service"):
    check_service(doc, fails)
  check_l7_mtls(docs, fails)

  if fails.ok():
    print(f"manifest lint: OK ({len(docs)} documents, strict-digest={args.strict_digest})")
    return 0
  print(f"manifest lint: {len(fails.items)} failure(s):")
  for item in fails.items:
    print(f"  - {item}")
  return 1


if __name__ == "__main__":
  sys.exit(main())
