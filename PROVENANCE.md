# Provenance

**Design**: this worked example implements, in real running code, the
checkpoint pattern proposed by **osr21** across three comments on
[`coinbase/agentkit#1141`](https://github.com/coinbase/agentkit/pull/1141)
(2026-10-30):

1. Event hashes bind `seq` + `prev_event_hash`; periodically anchor a
   checkpoint carrying schema/version, first/last seq, event count,
   `log_root`, and `previous_checkpoint_root`.
2. Bind the checkpoint producer's identity/key into the digest when
   attribution matters; record the on-chain anchor caller **separately**
   as `anchor_submitter` — it may be a relayer, not the log producer.
3. Carry a stable producer identity and an exact key fingerprint inside a
   **versioned, domain-separated** canonical preimage. Publish a
   **detached** signature over the checkpoint hash (kept outside the
   preimage, to avoid circularity) plus a verifiable key-to-producer
   binding and rotation/revocation history. The verifier must state
   whether identity is anchored by a registry, a signed key manifest, or
   only a self-asserted ID.

This is **our implementation of the pattern osr21 described**, not
something osr21 or Coinbase asked us to build, endorsed, or reviewed.

## Convergence with our own pre-existing specs

Most of what osr21 asked for in point 3 (signer identity + key model
inside the attestation, and a recomputable-vs-anchored distinction for
key material) is already covered by specs we published 3–4 months
earlier in `argentum-core`, independently of this thread:

| Spec | First commit | What it already covers |
|---|---|---|
| [`docs/spec/signing-trust-ref.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/signing-trust-ref.md) | `84de0e3`, 2026-06-21 | `signer_type` (`operator_key` / `agent_keypair` / `tee_attested` / `multi_party`) + `signer_id` — who signed, under what key model. |
| [`docs/spec/verifier-key-source-ref-v1.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/verifier-key-source-ref-v1.md) | `7dbef87`, 2026-06-28 | `key_source` (`embedded` / `published_jwks` / `pinned_registry` / `cached_prior`) and the explicit **recomputable vs. anchored** distinction osr21 was asking for. |
| [`docs/spec/revocation-ref.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/revocation-ref.md) | `5765cf9`, 2026-05-24 | Rotation/revocation (`revocation_ref`, `revocation_authority_ref`, `revocation_check_at_ms`) — not exercised in this example since no key is revoked here, but available to a real deployment. |

We have no evidence osr21 was aware of these specs; this looks like
independent convergence toward the same properties, not adoption of our
work. We did **not** invent parallel field names for this example —
`signer_type`/`signer_id` and the `signer_record`/`key_source` shape
below are reused directly from our own published vocabulary.

**One genuinely new piece**: none of our existing specs had an
append-only-log-checkpoint primitive before this (`log_root`,
`first_seq`/`last_seq`, `event_count`, `previous_checkpoint_root`) —
`argentum-core` never had a case needing it until this conversation.
That part of the preimage is new, built for this example.

**Honest adaptation note on `signer_record`**: `verifier-key-source-ref-v1.md`'s
`signer_record` schema was designed for *multi-signer admission* fixtures
(a conformance board checking whether several independent signers on one
fixture are each recomputable). This example has a single signer, so some
of that schema's purpose (e.g. comparing multiple legs) doesn't fully
apply — we still populate all 8 required fields honestly rather than
taking a shortcut subset, and `verify.py` checks the invariants that do
apply (`key_source_declared`, `signature_input_bound`,
`signer_identity_bound`, `recomputable_not_anchored`).

## What's real and what's synthetic

| Component | Status |
|---|---|
| `AnchorRegistry` contract, Base mainnet | **Real** — the same contract used across this worked-example series. |
| `anchor()` transaction | **Real**, once anchored — see `artifacts/anchor.json`. |
| Event log (`artifacts/log.json`) | **100% synthetic**, written for this example. Not any real agent's actual log — same conceptual shape only. |
| Ed25519 keypair | **Freshly generated for this example only.** No real-world value, no connection to any production signer. The private key is written in cleartext to `artifacts/sample_private_key_DO_NOT_USE.hex` purely so the example is reproducible — never do this with a real key. |
| `signer_record.key_source` | **`embedded`** — the public key ships inside the record itself. Per `verifier-key-source-ref-v1.md`'s own invariant 6 (`recomputable_not_anchored`): this makes the record *recomputable*, not *anchored*. The key was chosen by whoever produced this checkpoint (us) — there is no independent registry behind it. A real deployment wanting an anchored guarantee would use `key_source = pinned_registry` against a registry it doesn't control. |
| `signer_id` (checkpoint) vs. `anchor_submitter` (on-chain) | Recorded and verified as **separate roles**, per osr21's point 2 — even though in this example both happen to be us. A real deployment could have a relayer submit on behalf of a different log producer; `verify.py` checks the roles independently rather than assuming they're the same party. |

## Honesty notes

- No claim that osr21, Coinbase, or agentkit adopted, requested, or
  reviewed this implementation, or were aware of our prior specs.
- No claim of a third-party identity registry — `key_source = embedded`
  is explicitly self-asserted/recomputable, and `verify.py` says so in
  its output rather than letting a reader infer something stronger.
- `log.json` is fabricated example data (task/tool-call events), chosen
  only to exercise the hash-chain + checkpoint pattern.
