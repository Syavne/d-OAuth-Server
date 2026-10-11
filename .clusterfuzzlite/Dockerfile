# ClusterFuzzLite builder image (T4-3).
#
# Pinned to the Rust base builder; the nightly selection comes from
# `fuzz/rust-toolchain.toml` (nearest toolchain file to the working
# directory), so the root stable pin is never violated. `cargo-fuzz` is
# installed here so `build.sh` stays a plain build script.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1

RUN cargo install cargo-fuzz --locked

COPY . "$SRC/d-oauth-server"
WORKDIR "$SRC/d-oauth-server"

COPY .clusterfuzzlite/build.sh "$SRC/build.sh"
