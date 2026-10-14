# ClusterFuzzLite builder image (T4-3).
#
# Pinned to the Rust base builder. The base image bakes `RUSTUP_TOOLCHAIN`
# as an environment variable, which overrides any `rust-toolchain.toml`,
# so the nightly is selected here explicitly (it must match
# `fuzz/rust-toolchain.toml`, which governs the CI and local fuzz legs).
# The root stable pin is never violated. `cargo-fuzz` is installed here so
# `build.sh` stays a plain build script.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1

# Must match `fuzz/rust-toolchain.toml`: dated, not floating, so a
# dependency can never again outgrow a stale preinstalled nightly
# (`sqlx 0.9` needs rustc >= 1.94; the base image ships 1.91).
ENV RUSTUP_TOOLCHAIN=nightly-2026-10-01
# The base image already ships cargo-fuzz and `cargo install` is a no-op when
# it is present, so pin with --force: a cargo-fuzz that leaks the sanitizer
# RUSTFLAGS into host proc-macros breaks the build.
RUN rustup toolchain install nightly-2026-10-01 \
  && cargo install cargo-fuzz --locked --force --version 0.13.2

COPY . "$SRC/d-oauth-server"
WORKDIR "$SRC/d-oauth-server"

COPY .clusterfuzzlite/build.sh "$SRC/build.sh"
