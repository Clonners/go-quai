# NiPoPoW Proofs for Trust-Reduced Mining Templates

## Status

This document describes a staged, read-only NiPoPoW implementation for `go-quai`.

The current stack adds:

1. Prime-chain NiPoPoW proof primitives.
2. A Zone/Region -> Prime manifest wrapper verifier.
3. A pending-template proof source for the already-persisted hierarchy context behind a Zone mining template.
4. Explicit opt-in `nipopowProof` delivery in `quai_getBlockTemplate`.
5. Offline client-side verification helpers for pools/miners.
6. Local opt-in gate/proxy tooling for shadow-mode integration.

The implementation is intentionally non-consensus. It does not change block validation rules, fork choice, default mining behavior, or persisted chain state.

## Problem

Mining pools currently need to trust or whitelist nodes that provide block templates. A pool receiving a Zone block template from an untrusted node needs compact evidence that the template is backed by already-persisted Quai hierarchy context and sufficient Prime-chain work.

The desired verification shape is:

```text
Zone block template/header
  -> backed by a persisted Zone context
Zone context
  -> included in a Region manifest
Region context
  -> included in a Prime manifest
Prime manifest carrier
  -> tip of a compact Prime NiPoPoW proof
Prime proof
  -> verified by the pool/client under its local policy
```

Important caveat: the proof backs the already-selected persisted context behind a pending Zone template. It does not claim that the unmined template itself is already manifest-included.

## Goals

- Add compact Prime-chain proof representation and verification.
- Build proofs from already-persisted canonical chain data.
- Verify header/body binding, interlink roots, linear suffixes, interlink jumps, and wrapper manifest membership.
- Keep proof building read-only and context-cancellable.
- Keep public block-template behavior unchanged unless the caller explicitly opts in.
- Let a pool/client verify an opted-in template artifact offline, without DB access and without trusting the producing node.
- Bound RPC-exposed proof generation by timeout, proof size, proof length, manifest size, and `m` policy.

## Non-goals

- No consensus-rule changes.
- No fork-choice changes.
- No default block-template schema changes.
- No DB writes or recalculation of persisted interlinks.
- No public generic proof-verifier RPC that could be mistaken for a canonical truth oracle.
- No claim of complete mainnet-correctness until protocol/QIP semantics are reviewed by the Quai team.

## Code layout

- `core/nipopow/proof.go`
  - `Proof`
  - `VerifyPrimeProof`
  - structural Prime proof checks

- `core/nipopow/build.go`
  - `PrimeProofSource`
  - `BuildPrimeProof`
  - bounded canonical-chain proof construction

- `core/nipopow/pow.go`
  - optional PoW/rank verification helpers when a caller supplies the consensus PoW hash function

- `core/nipopow/score.go`
  - proof scoring/comparison helpers

- `core/nipopow/hierarchy.go`
  - `HierarchyProof`
  - `VerifyHierarchyProof`
  - Zone/Region -> Prime manifest-wrapper checks

- `core/nipopow/hierarchy_collect.go`
  - `HierarchyProofSource`
  - `HierarchyProofRequest`
  - `CollectHierarchyProofWithContext`

- `core/nipopow/template.go`
  - `TemplateHierarchyProof`
  - `BuildTemplateHierarchyProofWithContext`
  - derives the proof request from a Zone pending template's selected Zone/Region/Prime parent context

- `core/nipopow/template_verify.go`
  - `VerifyTemplateHierarchyProofArtifact`
  - offline artifact verifier for opted-in template proofs

- `core/nipopow/templateclient`
  - local pool/miner fetch-and-verify helper
  - local rate-limited proxy handler
  - fail-closed checks for missing proof, visible `quairoot`/seal-prefix binding, hierarchy verification, and proof-budget policy

- `internal/quaiapi/block_template_nipopow_policy.go`
  - budget/deployment policy for opted-in block-template proof generation

- `internal/quaiapi/quai_api.go`
  - bounded Prime-only `quai_getNiPoPoWProof` access
  - optional `nipopowProof` attachment in `quai_getBlockTemplate` when explicitly requested

- `cmd/nipopow-template-verify`
  - standalone JSON verifier for `nipopowProof` artifacts without DB or RPC

- `cmd/nipopow-template-gate`
  - one-shot local gate that requests an opted-in template, verifies it, and optionally strips the proof from accepted miner-facing output

- `cmd/nipopow-template-proxy`
  - local JSON-RPC proxy that forces upstream opt-in proof requests, verifies locally, caches accepted templates for equivalent downstream requests, and strips proof before returning miner-facing templates

- `cmd/nipopow-template-observe`
  - opt-in/default RPC sampler for controlled shadow-mode observation

- `cmd/nipopow-hierarchy-validate`
  - read-only snapshot validation CLI for explicit hierarchy-wrapper requests

## Safety model

The proof path is read-only infrastructure.

Safety properties:

1. Proof builders read persisted chain data only.
2. Builders avoid helper paths that can mutate storage.
3. Genesis and early-chain cases are handled explicitly.
4. Public proof construction is bounded by:
   - maximum chain walk length;
   - maximum proof header count;
   - maximum `m`;
   - context cancellation;
   - opt-in block-template proof timeout;
   - maximum Region/Prime manifest entry count;
   - maximum serialized `nipopowProof` bytes.
5. The structural verifier checks:
   - non-nil proof and headers;
   - valid `m`;
   - sufficient suffix length;
   - anchor consistency;
   - WorkObject header/body binding;
   - interlink root consistency;
   - forward-only interlink jumps;
   - linear final suffix;
   - Zone -> Region manifest membership;
   - Region -> Prime manifest membership;
   - Prime proof tip binding.
6. Default `quai_getBlockTemplate` responses stay proof-free.
7. Opted-in proof failures fail closed: the caller receives an explicit error instead of an unverifiable proof payload.

## Block-template opt-in API

Default request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "quai_getBlockTemplate",
  "params": [
    {"rules": ["kawpow"]}
  ]
}
```

Default response behavior is unchanged and omits `nipopowProof`.

Opted-in request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "quai_getBlockTemplate",
  "params": [
    {
      "rules": ["kawpow"],
      "nipopowProof": true,
      "nipopowProofM": 2
    }
  ]
}
```

Opted-in response behavior:

- Returns the normal block template fields.
- Adds `nipopowProof` only when explicitly requested.
- Applies request-budget policy before returning the proof.
- Returns an explicit error for opted-in proof failures.

## Offline client verification

A pool/client should treat the producing node as untrusted:

```text
producer node -> opt-in block template + nipopowProof
pool/client   -> local verifier, no DB, no RPC trust
miner-facing  -> accepted proof-stripped template, or fail closed
```

The local verifier checks:

- proof presence;
- visible `quairoot`/template-seal binding;
- template metadata binding;
- Zone/Region/Prime manifest wrapper binding;
- Prime proof structure;
- request-budget policy.

Example one-shot gate:

```bash
go run ./cmd/nipopow-template-gate \
  --rpc https://example.invalid \
  --m 2 \
  --strip-proof
```

Example local proxy self-test:

```bash
go run ./cmd/nipopow-template-proxy \
  --upstream https://example.invalid \
  --listen 127.0.0.1:8570 \
  --m 2 \
  --self-test-samples 2
```

## Request-budget policy

The default block-template proof policy is conservative:

- proof build timeout: 2s;
- max `m`: 64;
- max hierarchy/proof walk: bounded by `DefaultBuildLimits`;
- max Prime proof headers: bounded;
- max Region/Prime manifest hashes: bounded;
- max serialized proof bytes: bounded.

Rate limiting and authentication belong at the RPC gateway, pool adapter, or local proxy layer. The in-process API layer does not have reliable per-client identity.

## Generated evidence policy

Do not commit private deployment reports, live-node logs, local DB paths, PIDs, hostnames, wallet addresses, Tailscale/VPN details, or raw miner canary artifacts to the upstream PR.

If evidence is needed for review, provide a short sanitized summary or a deterministic test fixture that contains no local infrastructure details.

Generated outputs should be written outside the repo or under ignored report paths.

## Verification commands

Recommended local checks for this stack:

```bash
go test ./core/nipopow ./core/nipopow/templateclient ./cmd/nipopow-template-verify ./cmd/nipopow-template-gate ./cmd/nipopow-template-proxy ./cmd/nipopow-template-observe ./internal/quaiapi ./quai -count=1
go build ./cmd/go-quai ./cmd/nipopow-template-verify ./cmd/nipopow-template-gate ./cmd/nipopow-template-proxy ./cmd/nipopow-template-observe
git diff --check
```

## Remaining review questions

This stack is suitable for technical review, but the team still needs to confirm:

- QIP-0009 semantics for superblock scoring and verifier policy;
- exact Prime proof rank/difficulty policy expected by pools;
- stale/reorg behavior for template context;
- whether hierarchy proof fields belong in core, API, tooling, or a split package;
- how much pool-side tooling should live in-tree versus external adapters.
