#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
emsdk_root="$repo_root/.tools/emsdk"
emscripten_root="$emsdk_root/upstream/emscripten"
cmake="$repo_root/.tools/venv/bin/cmake"
ninja="$repo_root/.tools/venv/bin/ninja"
emcc="$emscripten_root/emcc"
emcmake="$emscripten_root/emcmake"
output_dir="$repo_root/web/static/wasm"
build_dir="$repo_root/build/wasm"

for tool in "$cmake" "$ninja" "$emcc" "$emcmake"; do
  if [[ ! -x "$tool" ]]; then
    printf 'Missing local tool: %s\n' "$tool" >&2
    exit 1
  fi
done

if ! "$emcc" --version | grep -Fq '6.0.8'; then
  printf 'The local Emscripten toolchain is not version 6.0.8.\n' >&2
  exit 1
fi

mkdir -p "$output_dir"
"$emcmake" "$cmake" -S "$repo_root" -B "$build_dir" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_MAKE_PROGRAM="$ninja" \
  -DWIRELENS_BUILD_TESTS=OFF \
  -DWIRELENS_WARNINGS_AS_ERRORS=ON
"$cmake" --build "$build_dir" --target wirelens_wasm --parallel

for asset in "$output_dir/wirelens.js" "$output_dir/wirelens.wasm"; do
  if [[ ! -s "$asset" ]]; then
    printf 'Expected non-empty WebAssembly asset was not produced: %s\n' "$asset" >&2
    exit 1
  fi
done

printf 'Emscripten: '
"$emcc" --version | sed -n '1p'
printf 'WebAssembly output: %s\n' "$output_dir"
