#!/bin/bash -eu
# ClusterFuzzLite build script (T4-3): compile every cargo-fuzz target and
# stage the binaries plus any checked-in seed corpus into $OUT.
#
# Hermetic by construction: every target exercises only pure parsers (no
# network, Postgres, or Redis), so the OSS-Fuzz sandbox needs no services.

cd "$SRC/d-oauth-server/fuzz"

# The OSS-Fuzz base image exports CXX=clang++ with a CXXFLAGS that selects
# libc++ (-stdlib=libc++). libfuzzer-sys's build script compiles libFuzzer's
# C++ runtime with those flags, but rustc/cc links the C++ stdlib as libstdc++
# (-lstdc++), so the runtime's libc++ (std::__1::) symbols end up undefined at
# link time. clang++ defaults to libstdc++ when the flag is absent, so drop it
# to make the compiled runtime and the link line agree.
CXXFLAGS="${CXXFLAGS:-}"
export CXXFLAGS="${CXXFLAGS//-stdlib=libc++/}"

cargo fuzz build -O --debug-assertions

for target_path in fuzz_targets/*.rs; do
  target="$(basename "$target_path" .rs)"
  cp "build/x86_64-unknown-linux-gnu/release/$target" "$OUT/" 2>/dev/null \
    || cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
  if [ -d "corpus/$target" ]; then
    zip -j "$OUT/${target}_seed_corpus.zip" "corpus/$target/"* 2>/dev/null || true
  fi
done
