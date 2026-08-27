# WireLens

WireLens is a local-first visual network protocol inspector. It reads a capture
file selected by the user and turns it into a small, evidence-based view of
packets, protocol layers, and conversations.

## Phase 1 scope

Phase 1 proves one synthetic TCP handshake from file to native C++, WebAssembly,
Web Worker, and static Svelte UI. It supports inspection of classic PCAP files
with Ethernet, IPv4, and TCP handshake facts. It does not claim the complete V1
protocol list yet. See the [protocol roadmap](docs/reference/filter-and-protocol-roadmap.md).

The application is local only. The selected file stays in the browser and is
not uploaded. Phase 1 has no live capture, packet transmission or replay,
scanning, probing, decryption, backend, telemetry, analytics, or account. The
hard limits are 64 MiB per file and 65,536 packets per capture. These are safety
limits, not performance claims.

## Quick start

Requirements are Node.js 22, pnpm 11.24.0, Python 3, ripgrep, CMake 4.4.2,
Ninja 1.13.0, and Emscripten 6.0.8. The CMake and Ninja tools can be installed
in a repository-local virtual environment:

```sh
./scripts/bootstrap-local-toolchain.sh
pnpm install --frozen-lockfile
```

Install Emscripten 6.0.8 in `.tools/emsdk` when you need a WebAssembly build.
The CI workflow shows the pinned setup. Then run the complete local gate:

```sh
pnpm verify:phase1
```

To open the local UI after the build:

```sh
pnpm --dir web dev
```

Choose `fixtures/generated/tcp-handshake.pcap` in the UI. The fixture is
original deterministic data; it is not traffic captured from a network
interface.

## Commands

| Command                     | Purpose                                                                         |
| --------------------------- | ------------------------------------------------------------------------------- |
| `pnpm verify:phase1`        | Run the fail-fast build, test, parity, privacy, secret, audit, and browser gate |
| `pnpm test`                 | Run schema, fixture, and web unit tests                                         |
| `pnpm check`                | Run TypeScript and project checks                                               |
| `pnpm lint`                 | Run package linters                                                             |
| `pnpm format:check`         | Check supported files with Prettier                                             |
| `pnpm test:parity`          | Compare native, WebAssembly, and golden JSON                                    |
| `pnpm --dir fixtures build` | Rebuild the synthetic PCAP                                                      |
| `pnpm --dir web build`      | Build the static web output                                                     |
| `pnpm --dir web dev`        | Start the local Vite development server                                         |

## Architecture

The C++20 core uses checked reads over bounded capture bytes. The native CLI and
Emscripten bridge use the same normalized JSON contract. A normal Web Worker
owns WebAssembly and validates the result before the Svelte UI reads it. Raw
packet bytes are not included in the normalized document. The browser uses
same-origin static assets only.

The contract source of truth is
[`schema/capture.schema.json`](schema/capture.schema.json). Its identifiers,
time strings, byte ranges, and compatibility rules are described in the
[Phase 1 contract reference](docs/reference/phase-1-contract.md).

## Limits and safety

Malformed input returns typed parse errors. The UI does not use raw packet text
as HTML and does not persist capture data in browser storage. Sanitized model
exports can still contain IP addresses, hostnames, and paths that identify a
system. Phase 1 does not export raw packet bytes.

This project is an inspector for learning and development. It is not an
intrusion-detection system and does not make threat or malware claims.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing the repository. Use a
short branch, keep changes inside the task scope, and run `pnpm verify:phase1`
before review when the required local tools are available.

## Security

See [SECURITY.md](SECURITY.md) for the local-only privacy model and reporting
process.
