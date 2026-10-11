# Minimal static-musl image for the d-OAuth OAuth 2.1 authorization server.
#
# 4 stages: chef -> planner -> builder -> runtime.
# - `chef`: pinned rust toolchain + cargo-chef + musl targets. No DB needed:
#   `SQLX_OFFLINE=true` builds against the committed `.sqlx/` query cache.
# - `planner`: captures the dependency recipe so dependency layers cache.
# - `builder`: cooks dependencies, then builds the locked, stripped,
#   fully-static musl binary (rustls `ring` provider only; no
#   aws-lc-sys/OpenSSL anywhere in the graph).
# - `runtime`: pinned-digest distroless `static-debian12:nonroot` (no shell,
#   no package manager, CA bundle + tzdata + nonroot /etc/passwd entry
#   included). Only the stripped binary is copied in.
#
# BuildKit cache mounts keep the cargo registry/git cache and the target
# directory warm across rebuilds without baking them into any layer.

# Pinned bases (multi-arch index digests; buildx selects per-platform):
# - rust 1.99-bookworm (matches rust-toolchain.toml stable; rustc 1.99.0)
# - distroless static-debian12:nonroot (UID:GID 65532, no shell)
ARG RUST_BASE=docker.io/library/rust:1.99-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0
ARG RUNTIME_BASE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM ${RUST_BASE} AS chef
WORKDIR /app
# Reproducible builds: fixed epoch (overridden by bake) and no incremental.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
  SQLX_OFFLINE=true \
  CARGO_INCREMENTAL=0 \
  CARGO_NET_RETRY=10
RUN cargo install cargo-chef --locked --version 0.1.78 \
  && apt-get update \
  && apt-get install -y --no-install-recommends musl-tools \
  && rm -rf /var/lib/apt/lists/* \
  && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG TARGETARCH
COPY --from=planner /app/recipe.json recipe.json
# Cook (compile) third-party dependencies only: this layer reuses the cache
# unless Cargo.toml/Cargo.lock change.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    sh -c 'if [ "$TARGETARCH" = "arm64" ]; then export RUST_TARGET=aarch64-unknown-linux-musl; else export RUST_TARGET=x86_64-unknown-linux-musl; fi && \
    rustup target add "$RUST_TARGET" && \
    cargo chef cook --locked --release --target "$RUST_TARGET" --recipe-path recipe.json --bin d-oauth-server'
COPY . .
# Locked, offline release build of the server binary only. The target dir is
# a cache mount, so the binary is copied out to /app/dist in the same layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    sh -c 'if [ "$TARGETARCH" = "arm64" ]; then export RUST_TARGET=aarch64-unknown-linux-musl; else export RUST_TARGET=x86_64-unknown-linux-musl; fi && \
    rustup target add "$RUST_TARGET" && \
    cargo build --locked --release --target "$RUST_TARGET" --bin d-oauth-server && \
    mkdir -p /app/dist && \
    cp "/app/target/$RUST_TARGET/release/d-oauth-server" /app/dist/d-oauth-server'

FROM ${RUNTIME_BASE} AS runtime
# Only the stripped static binary (release profile: lto thin, strip symbols).
COPY --from=builder /app/dist/d-oauth-server /d-oauth-server
# Non-root, exec-form entrypoint (no shell in the image to interpret one).
USER 65532:65532
# Public TLS listener (default bind_addr 0.0.0.0:8080). The plaintext health
# listener (default 0.0.0.0:8081, pod IP) is intentionally NOT published: it
# is probed by kubelet/HEALTHCHECK from inside the pod network only.
EXPOSE 8080
# Shell-less self-probe: the `healthcheck` subcommand speaks raw HTTP/1.1
# over loopback to the plaintext health listener (no shell, no TLS trust).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["/d-oauth-server", "healthcheck"]
ENTRYPOINT ["/d-oauth-server", "serve"]
LABEL org.opencontainers.image.title="d-oauth-server" \
  org.opencontainers.image.description="OAuth 2.1-only authorization server (static musl, non-root, no shell)" \
  org.opencontainers.image.licenses="MIT OR Apache-2.0" \
  org.opencontainers.image.source="https://github.com/d-oauth/d-oauth" \
  org.opencontainers.image.revision="unknown" \
  org.opencontainers.image.vendor="d-oauth"
