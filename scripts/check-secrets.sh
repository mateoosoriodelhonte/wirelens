#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo_root"

patterns='(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16})'

if rg -n --hidden --glob '!.git/**' --glob '!.tools/**' --glob '!build/**' \
  --glob '!web/static/wasm/**' --glob '!scripts/check-secrets.sh' --regexp "$patterns" .; then
  printf 'Potential secret material found.\n' >&2
  exit 1
fi

printf 'Secret scan: PASS\n'
