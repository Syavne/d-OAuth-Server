#!/bin/bash -eu
# ClusterFuzzLite build script (T4-3): compile every cargo-fuzz target and
# stage the binaries plus any checked-in seed corpus into $OUT.
#
# Hermetic by construction: every target exercises only pure parsers (no
# network, Postgres, or Redis), so the OSS-Fuzz sandbox needs no services.

cd "$SRC/d-oauth-server/fuzz"

# Drop the OSS-Fuzz sanitizer C flags. The base image prepends
# `-fsanitize=address ...` to CFLAGS/CXXFLAGS; the `cc`-compiled C/asm in a
# dependency (ring, pulled by sqlx's `tls-rustls-ring-webpki` feature) then
# carries ASan instrumentation. Those objects reach the *host* proc-macro
# `sqlx-macros` through its dependency graph, and because rustc does not link
# the ASan runtime into a proc-macro cdylib, that `.so` ends up with undefined
# `__asan_*`/`__sancov_lowest_stack` symbols and rustc cannot dlopen it while
# compiling `sqlx` (the scheduled `cflite-batch` failure). Dropping CXXFLAGS
# also lets clang++ default to libstdc++: the image's `-stdlib=libc++` would
# otherwise leave libFuzzer's C++ runtime (`std::__1::`) symbols undefined at
# link time. The Rust code keeps full ASan + libFuzzer coverage -- `cargo fuzz`
# supplies those Rust flags itself (the same scoped-flag mechanism `ci.yml
# fuzz-build` relies on, and it runs with no sanitizer env) -- and the C parts
# (libFuzzer runtime, ring) need no instrumentation for these pure-parser
# targets.
unset CFLAGS CXXFLAGS RUSTFLAGS

cargo fuzz build -O --debug-assertions

for target_path in fuzz_targets/*.rs; do
  target="$(basename "$target_path" .rs)"
  cp "build/x86_64-unknown-linux-gnu/release/$target" "$OUT/" 2>/dev/null \
    || cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
  if [ -d "corpus/$target" ]; then
    zip -j "$OUT/${target}_seed_corpus.zip" "corpus/$target/"* 2>/dev/null || true
  fi
done
