# Security policy

## Scope

WireLens Phase 1 is a local-only file inspector. It accepts a user-selected
capture file in the browser and parses it in a Web Worker. It does not capture
from an interface, send or replay packets, upload files, call a backend, use
telemetry, or store capture data in browser persistence.

The parser treats capture bytes as hostile. It uses bounded reads, a 64 MiB
input cap, and a 65,536-packet cap. Limit failures are typed parse results. The
normalized JSON contract excludes raw packet bytes. HTTP and future exports
must keep sensitive header values out of the model. A local-only design reduces
exposure, but it does not protect a compromised device or a malicious local
browser extension.

## Reporting

Do not post a suspected vulnerability with private capture files, credentials,
tokens, or personal data. Contact the repository owner through a private GitHub
security report when that feature is available. If it is not available, open a
minimal public issue with no sensitive details and request a private channel.

Include the affected commit, operating system, exact reproduction steps, and
impact. Remove secrets and packet contents from logs before sharing them.

## Safe development rules

- Never commit passwords, API keys, private keys, tokens, session data, or real capture files.
- Do not add network upload, remote scripts, analytics, or browser persistence.
- Validate untrusted bytes at parser boundaries and keep error details bounded.
- Treat generated JSON and model text as data; do not render it as HTML.
- Run `pnpm audit --audit-level high` and `bash scripts/check-secrets.sh` before review.
- Report missing, failed, and not-run security checks honestly.
