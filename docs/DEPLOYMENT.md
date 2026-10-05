# Deployment

The server ships as a minimal static image and runs as interchangeable
replicas in front of external Postgres and Redis. This guide covers the image,
the cluster contract, graceful shutdown, the mTLS network constraint, and the
supply-chain gates.

## Purpose

For an operator deploying the server: what the image contains, what the runtime
expects, and which constraints are enforced rather than advisory.

## The container image

The image is built by the four-stage `Dockerfile` in the repository root:

1. `chef`: a pinned Rust base plus `cargo-chef` and the two musl targets.
2. `planner`: captures the dependency recipe so dependency layers cache.
3. `builder`: cooks dependencies, then builds the locked, stripped, static musl
   binary. `SQLX_OFFLINE=true` builds against the committed `.sqlx/` cache, so
   the build needs no database.
4. `runtime`: a pinned-digest distroless `static-debian12:nonroot` base. It has
   no shell and no package manager. Only the stripped binary is copied in.

Properties the image guarantees:

- Static musl binary (`ldd` reports not a dynamic executable). The rustls
  `ring` provider is used, with no OpenSSL and no `aws-lc-sys` in the graph.
- Non-root `USER 65532:65532`.
- Exec-form `ENTRYPOINT ["/d-oauth-server", "serve"]`, so no shell interprets
  it.
- `EXPOSE 8080` for the TLS public listener. The plaintext health listener
  (default `0.0.0.0:8081`) is intentionally not published; it is probed inside
  the pod network only.
- `HEALTHCHECK` runs `["/d-oauth-server", "healthcheck"]`, which speaks raw
  HTTP/1.1 over loopback to the health listener. This works without a shell or
  curl.
- Reproducible: `SOURCE_DATE_EPOCH` is set, and the base images are pinned by
  digest.

Build with `docker buildx bake`, which reads `docker-bake.hcl`. The `image`
target builds both `linux/amd64` and `linux/arm64` by default. To build a single
architecture, override the platform:

```bash
# Both architectures (linux/amd64 + linux/arm64)
docker buildx bake image

# Single architecture
docker buildx bake image --set image.platform=linux/amd64
```

Building `linux/arm64` on an amd64 host requires QEMU binfmt emulation. Docker
Desktop bundles it; a bare Docker Engine does not. When it is missing, the arm64
leg fails fast with `exec /bin/sh: exec format error`, because BuildKit pulls
the real arm64 base image but the kernel cannot execute its arm64 binaries.
Register the handler once:

```bash
docker run --privileged --rm tonistiigi/binfmt --install arm64
```

The registration lives in `binfmt_misc` and does not survive a reboot; make it
durable with a `--restart=always` binfmt container or the distro's
`qemu-user-static` and `binfmt-support` packages. A single-architecture build,
such as `--set image.platform=linux/amd64`, needs no emulation and is the fast
local option. The full arm64 build runs every compile under emulation, so it is
noticeably slower than the amd64 build.

Then run the image:

```bash
docker run --rm -p 8080:8080 --read-only d-oauth-server:latest
```

The container needs its configuration from the environment, its TLS material
mounted read-only, and reachable Postgres and Redis. It holds no state itself,
so a read-only root filesystem is expected.

## TLS-terminating reverse proxy (HAProxy, Caddy)

The server always terminates TLS on `bind_addr`; there is no plaintext mode.
When a reverse proxy already holds the public certificate and terminates client
TLS (L7), point the proxy's HTTPS upstream at the server's TLS listener. The
server keeps its own certificate for the proxy-to-app hop, but that certificate
can be private, because only the proxy sees it. Keep verification on: rather
than disabling it, trust a private CA so the proxy verifies both the backend
chain and its hostname.

This L7 model cannot carry a client certificate, so it does not support
in-process client-certificate mTLS. For that, use L4/TCP passthrough or the
explicit trusted-proxy mode described below. Everything else, including DPoP,
PAR, and JAR, works unchanged.

### Generate a private CA and a server certificate

Create a small internal CA, then issue the server a `serverAuth` leaf whose SAN
matches the name the proxy verifies. Save this extension file next to the
certificates as `d-oauth.ext`:

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:d-oauth-backend,DNS:d-oauth.internal
```

```bash
# 1. Private internal CA. Keep internal-ca.key offline or in a secret manager.
openssl genrsa -out internal-ca.key 4096
openssl req -x509 -new -key internal-ca.key -sha256 -days 3650 \
  -subj "/CN=d-oauth internal CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out internal-ca.crt

# 2. Server key and CSR. The SAN below, not the CN, is what the proxy verifies.
openssl genrsa -out d-oauth.key 2048
openssl req -new -key d-oauth.key -subj "/CN=d-oauth-backend" -out d-oauth.csr

# 3. Sign the leaf with the internal CA.
openssl x509 -req -in d-oauth.csr \
  -CA internal-ca.crt -CAkey internal-ca.key -CAcreateserial \
  -days 825 -sha256 -extfile d-oauth.ext -out d-oauth.crt

chmod 0400 d-oauth.key
```

Mount `d-oauth.crt` and `d-oauth.key` read-only into the container at `/certs`
and set:

```bash
D_OAUTH_ISSUER=https://oauth.example.com
D_OAUTH_TLS__CERT_PATH=/certs/tls.crt
D_OAUTH_TLS__KEY_PATH=/certs/tls.key
```

Give the proxy `internal-ca.crt` so it can verify the backend. Confirm the leaf
before wiring the proxy:

```bash
openssl x509 -in d-oauth.crt -noout -ext subjectAltName -dates
openssl s_client -connect d-oauth-backend:8080 \
  -CAfile internal-ca.crt -verify_hostname d-oauth-backend </dev/null
```

### HAProxy

Terminate the public certificate on the frontend; verify the internal CA and the
SAN on the backend. Never use `verify none`, and never point `ca-file` at
`@system-ca`: the file must contain only the internal CA, so no public root can
be substituted to impersonate the backend.

```haproxy
frontend public-in
  mode http
  bind :443 ssl crt /etc/haproxy/certs/public-combined.pem alpn h2,http/1.1
  http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
  default_backend d_oauth

backend d_oauth
  mode http
  # `check` performs a TCP connect plus a TLS handshake; readiness is the
  # in-pod probe on the plaintext health listener (see the runbook).
  server app1 10.0.0.10:8080 ssl verify required ca-file /etc/haproxy/certs/internal-ca.crt verifyhost d-oauth-backend sni str(d-oauth-backend) check
```

`public-combined.pem` is the public leaf, its intermediates, and its private key
concatenated into one file. Validate with
`haproxy -c -f /etc/haproxy/haproxy.cfg`.

### Caddy

Caddy obtains and renews the public certificate automatically. Point the
upstream at the server over HTTPS and trust only the internal CA:

```caddy
oauth.example.com {
  reverse_proxy https://d-oauth-backend:8080 {
    transport http {
      tls
      tls_trust_pool file /etc/caddy/internal-ca.crt
      tls_server_name d-oauth-backend
    }
  }
}
```

Verification is on by default for an HTTPS upstream; `tls_trust_pool` replaces
the system roots with the internal CA, and `tls_server_name` pins the verified
name. Do not add `tls_insecure_skip_verify`; that is the only switch that
disables it. If the upstream address is an IP, keep `tls_server_name`, because
the address alone is not a verifiable name. Validate with
`caddy validate --config Caddyfile`.

### Proxy hardening

- Never disable backend verification: no `verify none` in HAProxy, no
  `tls_insecure_skip_verify` in Caddy, no `proxy_ssl_verify off` in nginx.
- Trust only the private CA. Do not append system roots, and pin the backend
  hostname (`verifyhost` / `tls_server_name`) so a different name under the same
  CA is still rejected.
- Keep the server's TLS port on the private network. Publish only the proxy; the
  app's `8080` must never be reachable from the host or the internet.
- Mount the key read-only at mode `0400`, readable by the runtime UID `65532`.
- Set `D_OAUTH_ISSUER` to the public `https://` URL; the app never sees the
  public hostname otherwise.
- Add HSTS at the proxy and keep modern TLS versions and ciphers on the public
  listener.
- Rotate by replacing the mounted material and performing a rolling restart;
  `serve` has no hot reload. Rotate before expiry and check with
  `openssl x509 -in d-oauth.crt -noout -checkend 2592000`.

## The cluster contract

A correct Deployment has these properties:

- Stateless replicas, three or more. Every replica shares the same external
  Postgres and Redis, so no replica holds state another needs.
- `runAsNonRoot`, `runAsUser: 65532`, `readOnlyRootFilesystem`, a
  `seccompProfile` of `RuntimeDefault`, `capabilities.drop: ["ALL"]`, and
  `automountServiceAccountToken: false`: the server never calls the Kubernetes
  API, so the projected service-account token would be pure attack surface.
- Resource requests and limits.
- A `startupProbe` and `livenessProbe` on `/health/live`, and a
  `readinessProbe` on `/health/ready`, all an HTTP GET against the plaintext
  health port. The public listener stays TLS-only.
- `terminationGracePeriodSeconds` greater than the drain deadline. The server
  uses a one second readiness propagation grace and a bounded drain below the
  grace budget.
- A `PodDisruptionBudget` with `minAvailable: 2`, and
  `topologySpreadConstraints` so replicas spread across nodes.
- A `Service`, a `ConfigMap` for non-secret settings (including the
  passwordless DSNs), and a `Secret` for secret material. Every secret is
  file-mounted under `/run/secrets` (see below), never injected into the
  environment or baked into the image.
- A `NetworkPolicy` that default-denies pod egress except DNS, Postgres, and
  Redis, and admits ingress only on the two pod ports (see below).
- A digest-pinned image reference. The release pipeline replaces the committed
  placeholder digest in `kustomization.yaml` with the signed build digest;
  `:latest` is never a shippable reference.
- Client-CA material mounted read-only if in-process mTLS is used. The Postgres
  CA for `sslmode=verify-full` is mounted at `/certs/db-ca.crt` and pinned with
  `database.root_cert_path` (`d-oauth-tls` also carries a `db-ca.crt` key).

### Migrations run once

Migrations are applied by a separate Job, never by the replicas. `serve` does
not migrate. The Job runs the `migrate` subcommand under sqlx's advisory lock,
so concurrent starts serialize and the schema is applied exactly once. The
Deployment readiness gate waits for the Job: a replica whose binary embeds a
migration that is not yet in `_sqlx_migrations` reports not ready.

Migrations must be expand/contract so version N-1 and N replicas serve during a
rollout. See [DATABASE.md](DATABASE.md).

### Secret material as files

The Deployment puts no secret in the environment. It projects every key of the
`d-oauth-secrets` Secret into a tmpfs volume at `/run/secrets`,
`defaultMode: 0400`, with the pod's `fsGroup` set to `65532`, and points the
loader at them:

```text
D_OAUTH_TOKEN_PEPPER_FILE=/run/secrets/token-pepper
D_OAUTH_TOTP_ENCRYPTION_KEY_FILE=/run/secrets/totp-encryption-key
D_OAUTH_DATABASE__PASSWORD_FILE=/run/secrets/database-password
D_OAUTH_REDIS__PASSWORD_FILE=/run/secrets/redis-password
```

The passwordless DSNs are non-secret and live in the ConfigMap
(`D_OAUTH_DATABASE__URL` with `sslmode=verify-full` and `D_OAUTH_REDIS__URL`);
only the passwords come from the Secret files. Only the runtime user/group can
read the files, so no credential or key material ever appears in
`/proc/self/environ`, in child processes, in `docker inspect` / `kubectl
describe` output, or in a crash dump — a `kubectl exec` into the container
reads nothing useful from the environment. `scripts/check_manifests.py` fails
the build if a workload injects a secret through a `secretKeyRef` env, or if a
ConfigMap DSN embeds a password. The inline `D_OAUTH_TOKEN_PEPPER` /
`D_OAUTH_TOTP_ENCRYPTION_KEY` forms remain supported and take precedence when
both are set (`src/config/build.rs`), so an existing environment-based
deployment still starts; the shipped manifests deliberately never set them.
The migrate Job mounts the same files. To rotate a password, update it in
Postgres/Redis and the Secret together, then roll the replicas; see
[CONFIGURATION.md](CONFIGURATION.md) and [OPERATIONS.md](OPERATIONS.md).

### Network policy

`networkpolicy.yaml` selects pods labeled
`app.kubernetes.io/name: d-oauth-server` (the app replicas and the migrate Job)
and enables both `Ingress` and `Egress` policy types, which makes it a
default-deny for those pods on any CNI that enforces NetworkPolicy (Calico,
Cilium, and similar). A CNI that ignores NetworkPolicy gets no benefit from the
manifest; verify the cluster CNI applies it.

- Egress admits DNS to the `kube-system` namespace on port 53 (UDP and TCP)
  and the Postgres (5432) and Redis (6379) ports to any address except
  `169.254.0.0/16`. The link-local exclusion means a cloud metadata endpoint
  such as `169.254.169.254` can never be reached, closing the SSRF-to-metadata
  and arbitrary-exfiltration paths.
- Ingress admits only the public TLS port (8080) and the plaintext health port
  (8081). The Service still publishes only 8080.
- If Postgres and Redis run in-cluster behind known labels, tighten the
  port-scoped `ipBlock` to their `namespaceSelector`/`podSelector`. If CoreDNS
  runs outside `kube-system`, adjust the DNS rule. A gateway in another
  namespace is still admitted because the ingress rule constrains ports, not
  sources.

The policy deliberately denies outbound HTTPS (443). The JAR `request_uri`
fetch (`src/jose/jar/fetch.rs`) retrieves a pre-registered request object from
a publicly routable HTTPS host, so it cannot reach its target under the shipped
default-deny. A deployment that relies on remote request objects must add a
scoped egress rule to that specific host on 443 — never a blanket 443
allowance, which would restore arbitrary exfiltration. A deployment that does
not can leave the default-deny in place and treat remote `request_uri` as
unavailable. The tension is recorded in [TODO.md](TODO.md).

### Multi-replica validation

A local compose file is the intended way to prove shared-state behavior: three
app replicas against one Postgres and one Redis, completing an
authorization-code flow whose token issued by one replica is introspectable via
another. The compose file is the local analogue of the cluster manifests.

## Optional: sandboxed runtime class

`RuntimeDefault` seccomp plus non-root, dropped capabilities, and a read-only
rootfs already block most post-RCE paths. A deployment that also wants to
contain a kernel or runtime escape can run under a sandboxed runtime class
(gVisor or Kata Containers). The manifests do not set `runtimeClassName`
because availability is cluster-specific: if the target cluster provides one,
set it on the Deployment and the migrate Job and verify that the health probes
and the Postgres/Redis connections still work under the sandboxed syscall
surface. A custom seccomp allowlist is deliberately not shipped — maintaining
one by hand across toolchain and dependency upgrades costs more than the
marginal reduction over `RuntimeDefault`. This is an operational option, not a
code change.

## Graceful shutdown

On `SIGTERM` the server:

1. Flips `/health/ready` to `503` immediately, so the endpoint is removed
   before connections close.
2. Waits a one second propagation grace so the kubelet observes it.
3. Drains in-flight requests under a bounded deadline.
4. Closes the pools and exits 0.

A `terminationGracePeriodSeconds` shorter than the drain deadline causes
in-flight requests to be cut off. Keep it above the budget.

## mTLS and the L7 constraint

In-process client-certificate verification needs the peer certificate to reach
the application. That requires L4/TCP passthrough at the load balancer
(a network load balancer gateway or a `TLSRoute`). An L7 ingress that terminates
TLS strips the client certificate, so in-process mTLS cannot work behind it.

Two correct options:

- Use L4/TCP passthrough so the server terminates TLS and sees the client
  certificate.
- Use the explicit trusted-proxy mode: terminate at a proxy you control, have it
  forward a verified client-cert representation, and set `trusted_proxy` to that
  proxy's address. When `trusted_proxy` is unset, forwarded client-cert headers
  are stripped.

This constraint is documented here and is not claimed to be exercised end to end
in CI. CI validates the manifests for the forbidden pairing of an L7 ingress
with client-cert auth. For a worked HAProxy and Caddy example that terminates
public TLS and re-encrypts to the backend while keeping certificate verification
on, see the TLS-terminating reverse proxy section above.

## Supply chain

The image pipeline is gated on:

- Multi-arch build with an SBOM and provenance attestation.
- A vulnerability scan (`trivy` or `grype`) that fails on HIGH and CRITICAL.
- Keyless signing with `cosign`.
- Digest pinning, with a periodic rebuild so base digests advance.
- `cargo deny check` in CI, which enforces the ring-only TLS policy in
  `deny.toml`.
- A per-PR fuzz build plus a scheduled bounded run of every fuzz target
  (`.github/workflows/ci.yml`); a crash uploads its artifact and fails the run.

## Security properties

- No shell and no package manager in the runtime image narrows the attack
  surface to the binary.
- Non-root with a read-only root filesystem.
- Secrets and CA material are mounted, never baked into the image or manifests.
- Every secret — token pepper, TOTP key, and the database and Redis passwords —
  is a `0400` tmpfs file, not an environment variable, and the pod carries no
  service-account token.
- `kubectl exec` / `docker exec` reach a non-root process with a read-only
  rootfs, no capabilities, and no shell, but still bypass the application's own
  auth; restrict `pods/exec` with RBAC and audit it (see
  [OPERATIONS.md](OPERATIONS.md)).
- A NetworkPolicy default-denies pod egress except DNS, Postgres, and Redis,
  and admits ingress only on the two pod ports.
- Health routes are unreachable from the public listener, so the probe port is
  not a second API surface.
- Liveness never touches a dependency, so a dependency outage does not trigger
  a restart storm.

## Edge cases

- A root or privileged pod violates the policy and must be rejected.
- An L7-terminated ingress with client-cert auth cannot carry the cert; use
  passthrough or trusted-proxy mode.
- Booting three replicas without the migration Job lets readiness block them
  until the schema matches.
- A replica that has no shared state is a bug: token state is in Redis, not in
  the process.
- A CNI that does not enforce NetworkPolicy leaves pod egress unrestricted;
  verify the cluster CNI applies the policy before relying on it.
- Shipping the committed placeholder digest without running the release
  pipeline fails closed: the image cannot be pulled. Run `pin-digest` first.

## Operational runbook

- Roll out a new image by updating the Deployment digest; the migration Job
  runs first.
- Probe commands inside the pod network:

```bash
wget -qO- http://<pod-ip>:8081/health/live
wget -qO- http://<pod-ip>:8081/health/ready
```

- The container healthcheck, usable without a shell:

```bash
d-oauth-server healthcheck --url http://127.0.0.1:8081/health/live
```

- On a rolling upgrade, watch that the PDB keeps at least two replicas ready
  and that readiness recovers after the drain.

## File and directory references

- `Dockerfile` for the four stages and runtime contract.
- `docker-bake.hcl` for the multi-arch targets.
- `.dockerignore` for the build context.
- `deny.toml` for the supply-chain policy.
- `RUNBOOK.md` for the admin bootstrap Job.
- `.github/workflows/ci.yml` for the quality and documentation gates.
- `.github/workflows/supply-chain.yml` for the image pipeline: multi-arch
  bake with SBOM + provenance, trivy/grype HIGH/CRITICAL gates, keyless
  cosign signing, digest pinning of `deploy/k8s/kustomization.yaml`, and the
  weekly rebuild.
- `deploy/k8s/` for the cluster manifests: `namespace.yaml`, `configmap.yaml`
  (non-secret settings only, including the passwordless DSNs), `secret.yaml`
  (placeholder secrets — pepper, TOTP key, database and Redis passwords — all
  file-mounted and replaced by the secret manager), `service.yaml` (public TLS
  port only, never the health port), `deployment.yaml` (3 stateless replicas,
  probes on the plaintext health listener, PDB + topology spread,
  `automountServiceAccountToken: false`, every secret file-mounted),
  `migrate-job.yaml` (exactly-once schema migration, never per replica),
  `networkpolicy.yaml` (default-deny egress except DNS/Postgres/Redis, ingress
  to the two pod ports), `pdb.yaml` (`minAvailable: 2`), `kustomization.yaml`
  (committed placeholder digest; the release pipeline pins the real image
  digest here), and `tls-secret.example.yaml` (how to provision `/certs`,
  never applied). No Ingress is shipped: mTLS requires L4/TCP passthrough.
- `compose.yaml` for the local 3-replica proof (one Postgres + one Redis,
  one-shot `migrate`, file-mounted dev secrets under `/run/secrets`, random
  host ports so `--scale app=3` never collides).
- `scripts/check_manifests.py` for the manifest policy lint, including the
  L7-ingress-with-client-cert-auth rejection.
