# SessionLayer — Canonical Cross-Repo Contracts

This directory is the **single source of truth** for every contract that crosses
a component boundary in SessionLayer. It is **contract-first** (Design §13,
FR-API-1): the contracts here are authored and frozen *before* any consumer
generates code, and every repo derives its types from these files — no repo
hand-writes a divergent copy.

It lives inside the `ControlPlane-API` repo (the CP owns the API surface), and is
vendored/generated-from by the other repos.

## Layout

```
contracts/
├── openapi/                 # REST contract (OpenAPI 3.1)
│   ├── openapi.yaml         #   the spec: /v1/healthz, /v1/version, security schemes, RFC 9457
│   └── README.md            #   how the spec is consumed by codegen
├── proto/                   # CP <-> Gateway gRPC contract (protobuf)
│   ├── buf.yaml             #   buf module: lint + breaking-change rules
│   ├── buf.gen.yaml         #   canonical (reference) codegen plugin set
│   └── sessionlayer/controlplane/v1/
│       ├── common.proto     #   ProtocolVersion, ComponentInfo
│       └── handshake.proto  #   Handshake.Negotiate (version negotiation) — the only RPC this session
├── wire/
│   └── agent-gateway-v1.md  # Agent <-> Gateway wire-protocol SPECIFICATION (doc, not code)
├── redocly.yaml             # OpenAPI linter config (Redocly CLI)
├── lint.sh                  # single entrypoint: buf lint + buf breaking + redocly lint
├── VERSIONING.md            # the N-1 compatibility policy (D33/§16A, FR-HA-9)
└── README.md                # this file
```

## Who consumes what

| Repo | Consumes | How it generates |
|---|---|---|
| **ControlPlane-API** (Java) | `proto/` (server), `openapi/` (server interfaces) | `protobuf-maven-plugin` + `protoc-gen-grpc-java`; `openapi-generator-maven-plugin` (spring/webflux) — build fails on drift |
| **Gateway** (Rust) | `proto/` (client) | `tonic-build` / `prost-build` in `build.rs` against a vendored copy of `proto/` |
| **Agent** (Rust) | `proto/common.proto` (types), `wire/` (spec) | `tonic-build` / `prost-build` in `build.rs` |
| **ControlPlane-Dashboard** (TS) | `openapi/` | `openapi-typescript` + `openapi-fetch`; CI fails if the checked-in client drifts |

Because the parent `SessionLayer/` folder is **not** a git repo, consumers in
other repos vendor the proto/openapi files (documented per repo) rather than
referencing them by a relative path across repos. The authoritative copy is
always the one here.

## Linting (CI merge gate)

```bash
contracts/lint.sh      # buf lint + buf breaking (vs main) + redocly lint
```

Requires `buf` and a Node/`npx` toolchain on PATH. `buf breaking` compares
against the `main` baseline and is skipped only on the very first introduction
(when `main` has no `contracts/proto` yet). This script is wired into the
ControlPlane-API CI and the repo gate.

## Freeze discipline

The contract is **frozen at the start of each session before fan-out**. If a
contract must change after freeze, every consumer is re-notified and the change
goes through the versioning procedure in `VERSIONING.md`. Breaking changes are
mechanically caught by `buf breaking`.
