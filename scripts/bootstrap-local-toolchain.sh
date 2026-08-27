#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
tool_dir=${WIRELENS_TOOL_DIR:-"$repo_root/.tools"}
venv_dir="$tool_dir/venv"
python_bin=${PYTHON_BIN:-python3}

print_paths() {
  printf 'Tool directory: %s\n' "$tool_dir"
  printf 'CMake: %s\n' "$venv_dir/bin/cmake"
  printf 'Ninja: %s\n' "$venv_dir/bin/ninja"
  printf 'Clang format: %s\n' "$venv_dir/bin/clang-format"
  printf 'Activate: export PATH=%s/bin:$PATH\n' "$venv_dir"
}

if [[ ${1:-} == "--print-paths" ]]; then
  print_paths
  exit 0
fi

"$python_bin" -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install \
  --disable-pip-version-check \
  --no-input \
  'cmake==4.4.2' \
  'ninja==1.13.0' \
  'clang-format==21.1.8'

print_paths
