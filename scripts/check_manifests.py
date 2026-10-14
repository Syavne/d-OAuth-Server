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
- Hardening: `automountServiceAccountToken: false` and `fsGroup: 65532`; every
  secret (token pepper, TOTP key, mandatory PII key, database and Redis
  passwords) must be file-mounted from `d-oauth-secrets` at `/run/secrets`
  (`defaultMode: 0400`) and referenced with its `*_FILE` variable; the inline
  `D_OAUTH_TOKEN_PEPPER` / `D_OAUTH_TOTP_ENCRYPTION_KEY` /
  `D_OAUTH_PII_ENCRYPTION_KEY` / `D_OAUTH_PII_PREVIOUS_KEY` /
  `D_OAUTH_TOTP_PREVIOUS_KEY` envs FAIL, and any workload env that injects a
  secret FAILS (`secretKeyRef`, `envFrom.secretRef`, a literal value embedding a
  DSN password, or a workload redefinition of `D_OAUTH_DATABASE__URL` /
  `D_OAUTH_REDIS__URL`). The PII key is mandatory in every workload; the
  previous PII/TOTP keys are OPTIONAL, but any `*_PREVIOUS_KEY_FILE` reference
  must point at `/run/secrets/<basename>` with `<basename>` actually projected
  by the secret volume's `items`.
- ConfigMap: the ConfigMap referenced by a workload `envFrom` must provide the
  passwordless `D_OAUTH_DATABASE__URL` / `D_OAUTH_REDIS__URL` DSNs, and neither
  may embed a password (it belongs in the Secret, read through the
  `*_PASSWORD_FILE` form).
- NetworkPolicy: must select `app.kubernetes.io/name: d-oauth-server`, enable
  `Ingress` + `Egress`, admit ingress only on 8080/8081, allow egress only on
  53 (DNS), 5432 (Postgres), and 6379 (Redis), forbid an internet-wide
  `0.0.0.0/0` egress peer, and require any `ipBlock` peer to exclude
  `169.254.0.0/16` (cloud metadata).
- No baked secrets: no PEM blocks in manifests; `REPLACE_ME` placeholders
  only inside `secret.yaml`; no secret-shaped keys in the ConfigMap.
- L7-vs-L4 mTLS constraint: an L7 Ingress that terminates TLS while
  in-process client-cert auth is enabled (`D_OAUTH_TLS__CLIENT_CA_PATH`
  set, or client-cert Ingress annotations) FAILS. mTLS needs L4/TCP
  passthrough (NLB gateway / TLSRoute); forwarded client-cert headers are
  never trusted.
  This constraint is DOCUMENTED (docs/DEPLOYMENT.md) and lint-checked
  here; it is explicitly NOT exercised end-to-end in CI.

Usage:
  python3 scripts/check_manifests.py [--manifest-dir deploy/k8s]
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

import yaml

HEALTH_PORT = 8081
PUBLIC_PORT = 8080
TERMINATION_GRACE_MIN = 45
SECRET_NAME_RE = re.compile(
  r"(?i)("
  r"pepper|password|secret|private[_-]?key"
  r"|pii[_-]?encryption[_-]?key(?!_id)"
  r"|pii[_-]?previous[_-]?key(?!_id)"
  r"|totp[_-]?previous[_-]?key(?!_id)"
  r"|totp[_-]?(encryption[_-]?)?key(?!_id)"
  r")"
)
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|-----BEGIN CERTIFICATE-----")
HIGH_ENTROPY_VALUE_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")
# A DSN that carries `user:password@` (or `:password@`) embeds a credential.
EMBEDDED_PASSWORD_RE = re.compile(r"://[^/@?#]*:[^/@?#]*@")

CLIENT_CERT_ANNOTATIONS = (
  "nginx.ingress.kubernetes.io/auth-tls-verify-client",
  "nginx.ingress.kubernetes.io/auth-tls-secret",
  "haproxy.org/ssl-verify-client",
  "traefik.ingress.kubernetes.io/router.tls.options",
)

SECRET_NAME = "d-oauth-secrets"
SECRETS_MOUNT_PATH = "/run/secrets"
FS_GROUP = 65532
SECRET_VOLUME_MODE = 0o400
FILE_SECRET_ENV_KEYS = {
  "D_OAUTH_TOKEN_PEPPER_FILE": "token-pepper",
  "D_OAUTH_TOTP_ENCRYPTION_KEY_FILE": "totp-encryption-key",
  "D_OAUTH_PII_ENCRYPTION_KEY_FILE": "pii-encryption-key",
  "D_OAUTH_DATABASE__PASSWORD_FILE": "database-password",
  "D_OAUTH_REDIS__PASSWORD_FILE": "redis-password",
}
INLINE_SECRET_ENVS = (
  "D_OAUTH_TOKEN_PEPPER",
  "D_OAUTH_TOTP_ENCRYPTION_KEY",
  "D_OAUTH_PII_ENCRYPTION_KEY",
  "D_OAUTH_PII_PREVIOUS_KEY",
  "D_OAUTH_TOTP_PREVIOUS_KEY",
)
# The previous keys are OPTIONAL, so their `_FILE` forms are not in
# FILE_SECRET_ENV_KEYS (that set is mandatory in every workload). They are
# still secret-shaped, so a workload that references them must file-mount them.
OPTIONAL_FILE_SECRET_ENVS = (
  "D_OAUTH_PII_PREVIOUS_KEY_FILE",
  "D_OAUTH_TOTP_PREVIOUS_KEY_FILE",
)
OPTIONAL_FILE_SECRET_RE = re.compile(
  rf"^{re.escape(SECRETS_MOUNT_PATH)}/(?P<basename>[^/]+)$"
)
PASSWORDLESS_DSN_KEYS = ("D_OAUTH_DATABASE__URL", "D_OAUTH_REDIS__URL")
REQUIRED_EGRESS_PORTS = (53, 5432, 6379)
METADATA_CIDR = "169.254.0.0/16"


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


def check_configmap(doc: dict, fails: Failures, requires_dsn: bool) -> None:
  data = doc.get("data") or {}
  for key in data:
    if SECRET_NAME_RE.search(key):
      fails.add(f"configmap: secret-shaped key {key!r} must live in the Secret")
  if not requires_dsn:
    return
  for key in PASSWORDLESS_DSN_KEYS:
    value = (data.get(key) or "").strip()
    if not value:
      fails.add(
        f"configmap: {key} is required; the workloads take the DSN from here "
        "and the password from the mounted *_PASSWORD_FILE"
      )
    elif EMBEDDED_PASSWORD_RE.search(value):
      fails.add(
        f"configmap: {key} must not embed a password; move it to the Secret "
        "and use the *_PASSWORD_FILE form"
      )


def referenced_configmaps(docs: list[dict]) -> set[str]:
  """Names of ConfigMaps any workload pulls into the environment via `envFrom`."""
  names: set[str] = set()
  for kind in ("Deployment", "Job"):
    for doc in by_kind(docs, kind):
      tpl = (doc.get("spec") or {}).get("template", {}).get("spec", {})
      for container in tpl.get("containers") or []:
        for ref in container.get("envFrom") or []:
          name = ((ref or {}).get("configMapRef") or {}).get("name")
          if name:
            names.add(name)
  return names


def mtls_enabled(docs: list[dict]) -> bool:
  for doc in by_kind(docs, "ConfigMap"):
    data = doc.get("data") or {}
    if (data.get("D_OAUTH_TLS__CLIENT_CA_PATH") or "").strip():
      return True
  return False


def octal_mode(value: object) -> int | None:
  """Parse a YAML file mode (`0400`, `0o400`, `256`) into an int, or None."""
  if isinstance(value, bool) or value is None:
    return None
  if isinstance(value, int):
    return value
  if isinstance(value, str):
    text = value.strip().lower().replace("_", "")
    try:
      if text.startswith("0o"):
        return int(text[2:], 8)
      if text.startswith("0") and len(text) > 1:
        return int(text, 8)
      return int(text, 10)
    except ValueError:
      return None
  return None


def env_by_name(container: dict) -> dict[str, dict]:
  envs: dict[str, dict] = {}
  for entry in container.get("env") or []:
    if isinstance(entry, dict) and entry.get("name"):
      envs[entry["name"]] = entry
  return envs


def check_file_mounted_secrets(
  workload: str, tpl: dict, container: dict, fails: Failures
) -> None:
  """Item 7: pepper/TOTP are 0400 files under /run/secrets, never inline env."""
  cname = container.get("name", "?")
  envs = env_by_name(container)
  for ref in container.get("envFrom") or []:
    if isinstance(ref, dict) and "secretRef" in ref:
      fails.add(
        f"{workload}/{cname}: envFrom.secretRef injects every secret into the "
        "environment; mount the keys as files instead"
      )
  for name, entry in envs.items():
    if "secretKeyRef" in (entry.get("valueFrom") or {}):
      fails.add(
        f"{workload}/{cname}: env {name} injects a secret via secretKeyRef; "
        "mount it as a file and reference the *_FILE form"
      )
    if name in PASSWORDLESS_DSN_KEYS:
      fails.add(
        f"{workload}/{cname}: {name} must come from the ConfigMap, not the "
        "workload env (an inline value could embed a password)"
      )
    value = entry.get("value")
    if isinstance(value, str) and EMBEDDED_PASSWORD_RE.search(value):
      fails.add(
        f"{workload}/{cname}: env {name} embeds a password; mount it as a file"
      )
  for inline in INLINE_SECRET_ENVS:
    if inline in envs:
      fails.add(
        f"{workload}/{cname}: {inline} must not be injected as an env value; "
        "use the file-mounted *_FILE form"
      )
  mount = next(
    (
      m
      for m in container.get("volumeMounts") or []
      if isinstance(m, dict) and m.get("mountPath") == SECRETS_MOUNT_PATH
    ),
    None,
  )
  if mount is None:
    fails.add(
      f"{workload}/{cname}: must mount the secret volume at {SECRETS_MOUNT_PATH}"
    )
  elif mount.get("readOnly") is not True:
    fails.add(f"{workload}/{cname}: {SECRETS_MOUNT_PATH} must be readOnly")
  items: dict[str, str] = {}
  mode: int | None = None
  for volume in tpl.get("volumes") or []:
    if not isinstance(volume, dict):
      continue
    secret = volume.get("secret") or {}
    if secret.get("secretName") != SECRET_NAME:
      continue
    mode = octal_mode(secret.get("defaultMode"))
    for item in secret.get("items") or []:
      if isinstance(item, dict) and item.get("key") and item.get("path"):
        items[item["key"]] = item["path"]
  if mode != SECRET_VOLUME_MODE:
    fails.add(f"{workload}: {SECRET_NAME} volume defaultMode must be 0400")
  for env_name, key in FILE_SECRET_ENV_KEYS.items():
    if key not in items:
      fails.add(f"{workload}: {SECRET_NAME} volume must project key {key!r}")
      continue
    expected = f"{SECRETS_MOUNT_PATH}/{items[key]}"
    entry = envs.get(env_name) or {}
    if (entry.get("value") or "").strip() != expected:
      fails.add(f"{workload}/{cname}: {env_name} must point at {expected}")
  for env_name in OPTIONAL_FILE_SECRET_ENVS:
    entry = envs.get(env_name)
    if entry is None:
      continue
    value = (entry.get("value") or "").strip()
    match = OPTIONAL_FILE_SECRET_RE.fullmatch(value)
    if match is None:
      fails.add(
        f"{workload}/{cname}: {env_name} must point at "
        f"{SECRETS_MOUNT_PATH}/<basename>, not a literal value"
      )
      continue
    basename = match.group("basename")
    if basename not in set(items.values()):
      fails.add(
        f"{workload}/{cname}: {env_name} points at {value} but the "
        f"{SECRET_NAME} volume does not project {basename!r}"
      )


def policy_ports(rule: dict) -> set[int]:
  ports: set[int] = set()
  for port in rule.get("ports") or []:
    if isinstance(port, dict) and isinstance(port.get("port"), int):
      ports.add(port["port"])
  return ports


def ip_network_contains(cidr: str, inner: str) -> bool:
  try:
    outer = ipaddress.ip_network(cidr)
    sub = ipaddress.ip_network(inner)
  except ValueError:
    return False
  if outer.version != sub.version:
    return False
  return (
    int(sub.network_address) >= int(outer.network_address)
    and int(sub.broadcast_address) <= int(outer.broadcast_address)
  )


def check_networkpolicy(doc: dict, fails: Failures) -> None:
  """Item 9: default-deny ingress/egress for the app pods."""
  name = doc.get("metadata", {}).get("name", "?")
  spec = doc.get("spec") or {}
  selector = (spec.get("podSelector") or {}).get("matchLabels") or {}
  if selector.get("app.kubernetes.io/name") != "d-oauth-server":
    fails.add(
      f"networkpolicy/{name}: podSelector must match "
      "app.kubernetes.io/name: d-oauth-server"
    )
  if not {"Ingress", "Egress"} <= set(spec.get("policyTypes") or []):
    fails.add(f"networkpolicy/{name}: policyTypes must include Ingress and Egress")
  ingress_ports: set[int] = set()
  for rule in spec.get("ingress") or []:
    if isinstance(rule, dict):
      ingress_ports |= policy_ports(rule)
  if not {PUBLIC_PORT, HEALTH_PORT} <= ingress_ports:
    fails.add(
      f"networkpolicy/{name}: ingress must admit ports "
      f"{PUBLIC_PORT} and {HEALTH_PORT}"
    )
  egress_ports: set[int] = set()
  for rule in spec.get("egress") or []:
    if not isinstance(rule, dict):
      continue
    egress_ports |= policy_ports(rule)
    for peer in rule.get("to") or []:
      block = (peer or {}).get("ipBlock") or {}
      cidr = block.get("cidr")
      if not cidr:
        continue
      if cidr in ("0.0.0.0/0", "::/0"):
        fails.add(
          f"networkpolicy/{name}: egress peer {cidr} is internet-wide; scope "
          "Postgres/Redis to a namespace/pod selector or a specific CIDR"
        )
      elif ip_network_contains(cidr, METADATA_CIDR) and METADATA_CIDR not in (
        block.get("except") or []
      ):
        fails.add(
          f"networkpolicy/{name}: egress ipBlock {cidr} must exclude "
          f"{METADATA_CIDR} (cloud metadata)"
        )
  for port in REQUIRED_EGRESS_PORTS:
    if port not in egress_ports:
      fails.add(f"networkpolicy/{name}: egress must allow port {port}")


def check_deployment(doc: dict, fails: Failures) -> None:
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
  if tpl.get("automountServiceAccountToken") is not False:
    fails.add(f"deployment/{name}: automountServiceAccountToken must be false")
  if pod_sc.get("fsGroup") != FS_GROUP:
    fails.add(
      f"deployment/{name}: fsGroup must be {FS_GROUP} so the 0400 secret "
      "files are readable by the runtime user"
    )
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
    check_file_mounted_secrets(f"deployment/{name}", tpl, container, fails)


def check_job(doc: dict, fails: Failures) -> None:
  name = doc.get("metadata", {}).get("name", "?")
  spec = doc.get("spec", {}).get("template", {}).get("spec", {})
  if spec.get("restartPolicy") != "Never":
    fails.add(f"job/{name}: restartPolicy must be Never")
  if spec.get("automountServiceAccountToken") is not False:
    fails.add(f"job/{name}: automountServiceAccountToken must be false")
  if (spec.get("securityContext") or {}).get("fsGroup") != FS_GROUP:
    fails.add(
      f"job/{name}: fsGroup must be {FS_GROUP} so the 0400 secret files are "
      "readable by the runtime user"
    )
  containers = spec.get("containers", [])
  if not any(
    "migrate" in " ".join(str(a) for a in (list(c.get("command", [])) + list(c.get("args", []))))
    for c in containers
  ):
    fails.add(f"job/{name}: exactly one migrate Job must run `/d-oauth-server migrate`")
  for container in containers:
    check_file_mounted_secrets(f"job/{name}", spec, container, fails)


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
        "passthrough (NLB gateway / TLSRoute); forwarded client-cert "
        "headers are never trusted"
      )


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--manifest-dir", default="deploy/k8s")
  args = parser.parse_args()

  fails = Failures()
  docs, load_fails = load_manifests(Path(args.manifest_dir))
  fails.items.extend(load_fails.items)

  kinds = {d.get("kind") for d in docs}
  for required in (
    "Deployment",
    "Service",
    "ConfigMap",
    "Secret",
    "Job",
    "PodDisruptionBudget",
    "NetworkPolicy",
  ):
    if required not in kinds:
      fails.add(f"missing required kind: {required}")

  check_pem_and_placeholders(docs, fails)
  required_dsn_configmaps = referenced_configmaps(docs)
  for doc in by_kind(docs, "ConfigMap"):
    name = (doc.get("metadata") or {}).get("name")
    check_configmap(doc, fails, requires_dsn=name in required_dsn_configmaps)
  for doc in by_kind(docs, "Deployment"):
    check_deployment(doc, fails)
  for doc in by_kind(docs, "Job"):
    check_job(doc, fails)
  for doc in by_kind(docs, "PodDisruptionBudget"):
    check_pdb(doc, fails)
  for doc in by_kind(docs, "Service"):
    check_service(doc, fails)
  for doc in by_kind(docs, "NetworkPolicy"):
    check_networkpolicy(doc, fails)
  check_l7_mtls(docs, fails)

  if fails.ok():
    print(f"manifest lint: OK ({len(docs)} documents)")
    return 0
  print(f"manifest lint: {len(fails.items)} failure(s):")
  for item in fails.items:
    print(f"  - {item}")
  return 1


if __name__ == "__main__":
  sys.exit(main())
