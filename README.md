# checkpoint-producer-binding-ref-anchor

A worked example implementing, in real running code, the checkpoint /
key-binding pattern proposed by **osr21** in
[`coinbase/agentkit#1141`](https://github.com/coinbase/agentkit/pull/1141)
(2026-10-30): a hash-chained event log, a versioned/domain-separated
checkpoint preimage carrying `signer_type`/`signer_id`
([`signing-trust-ref.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/signing-trust-ref.md),
first commit 2026-06-21), a detached signature kept outside the hashed
preimage, a `signer_record` declaring `key_source`
([`verifier-key-source-ref-v1.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/verifier-key-source-ref-v1.md),
first commit 2026-06-28), and an on-chain anchor with the anchor
transaction's sender tracked as a role (`anchor_submitter`) distinct from
the checkpoint's `signer_id`.

> **Provenance, up front (read `PROVENANCE.md` for the full statement).**
> This is our implementation of osr21's design. Most of the identity/key
> vocabulary already existed in our own specs 3-4 months earlier —
> this looks like independent convergence, not adoption of our work; we
> have no evidence osr21 knew of these specs. The event log is 100%
> synthetic. `key_source = embedded` is recomputable, not anchored —
> `verify.py` reports that distinction explicitly.

## The pattern

```
event_1 → event_2 → ... → event_12          (seq + prev_event_hash chain)
                              │
                              ▼  log_root = event_12.event_hash
                    ┌────────────────────────────┐
                    │ checkpoint preimage          │
                    │  domain, log_scope,          │  JCS + SHA-256
                    │  first/last_seq, count,      │ ───────────────▶ checkpoint_hash
                    │  log_root, prev_ckpt_root,   │
                    │  signer_type, signer_id      │  (signing-trust-ref.md vocabulary)
                    └────────────────────────────┘
                              │
              ┌───────────────┴────────────────┐
              ▼                                 ▼
   detached Ed25519 signature          AnchorRegistry.anchor(checkpoint_hash)
   (kept OUTSIDE the preimage,          Anchored(ref, anchor_submitter, time)
    avoids circularity)                 anchor_submitter tracked separately
                                         from signer_id
              │
              ▼
   signer_record {signer_id, key_id, key_source,
     public_key_hash, signature_input_hash,
     verification_result, key_resolution_time, ...}
   per verifier-key-source-ref-v1.md
   (key_source = embedded -> recomputable, not anchored)
```

## What's here

| Path | What it is |
|---|---|
| `scripts/generate_log.py` | Builds the synthetic 12-event hash-chained log. |
| `scripts/build_checkpoint.py` | Generates the Ed25519 sample key, builds the checkpoint preimage (`signing-trust-ref.md` vocabulary), computes `checkpoint_hash`, produces the detached signature and the `signer_record` (`verifier-key-source-ref-v1.md` shape). |
| `scripts/anchor.sh` | Equivalent `cast` command to anchor `checkpoint_hash`. |
| `verifier/verify.py` | Independent, from-scratch verifier: recomputes the log chain, recomputes `checkpoint_hash`, verifies the signature, checks `signer_record` against `verifier-key-source-ref-v1.md`'s invariants, and (once anchored) re-fetches the `Anchored` event directly from Base mainnet RPC and reports `anchor_submitter` as a role separate from `signer_id`. |
| `artifacts/` | `log.json`, `checkpoint.json`, `checkpoint_hash.json`, `signature.json`, `signer_record.json`, and (once anchored) `anchor.json`. |
| `scripts/generate_negative_fixtures.py` / `fixtures/negative/` / `verifier/verify_negative.py` | Six deliberately broken artifact sets + a from-scratch verifier that asserts each is rejected with its own reason code. See below. |
| `PROVENANCE.md` | Full honesty statement, including the convergence claim with exact commit hashes/dates — read it. |

## Negative fixtures

osr21 reviewed this worked example and asked (`coinbase/agentkit#1141`,
2026-11-01) for packaged negative cases, fail-closed with a reason code
each — not a single pass/fail boolean, same style as argentum-core's own
negative conformance vectors (`action-ref-v1-domain-negative/`,
`near-miss-v1/`). `verifier/verify_negative.py` recomputes each one from
scratch (never trusts a cached field — `key_substitution`'s own
`signer_record.verification_result` says `"pass"`; the point is that a real
verifier must not read that):

| Case | Reason code | What's broken |
|---|---|---|
| `key_substitution` | `SIGNATURE_KEY_MISMATCH` | `signer_id`/`signer_record` both claim key A; the signature was produced by a different key B. |
| `sequence_gap` | `LOG_SEQUENCE_GAP` | Hash chain is fully valid (every `prev_event_hash` correctly links); the `seq` labels have a hole (`1,2,3,5,6`). |
| `sequence_reorder` | `LOG_SEQUENCE_REORDERED` | Hash chain is fully valid; the `seq` labels are non-monotonic (`1,2,4,3,5,6`). |
| `wrong_log_root` | `CHECKPOINT_LOG_ROOT_MISMATCH` | Checkpoint's `log_root` points at an earlier event's hash, not the log's real tip. |
| `anchor_tx_reverted` | `ANCHOR_TX_REVERTED` | A synthetic captured receipt (`status: "0x0"`) — labeled as synthetic in the fixture itself; nothing was deliberately reverted on-chain to produce this. |
| `anchor_wrong_event` | `ANCHOR_EVENT_MISMATCH` | Reuses this repo's real, already-anchored tx (`artifacts/anchor.json`) but checks it against a `checkpoint_hash` it did *not* anchor — the chain data is real, the fixture's expectation is deliberately wrong. |

`sequence_gap` and `sequence_reorder` are built so the hash chain itself
stays valid (every link positionally correct) — isolating "the claimed
numbering has a hole / goes backwards" from "the chain was tampered with",
which is a different failure (`LOG_CHAIN_BREAK` / `LOG_EVENT_HASH_MISMATCH`,
also implemented, just not one of the six named cases here).

```bash
python3 scripts/generate_negative_fixtures.py
python3 verifier/verify_negative.py
```

**Already resolved by design, not new work for this request:** osr21 also
raised separating "signature verifies" from "key is bound to a known
identity." `verify.py` already keeps these apart —
`verification_result_recomputed` (line 94) is the raw Ed25519 check,
independent of any key-authority claim, and lines 161–168 print this
explicitly:

```
GUARANTEE TYPE (verifier-key-source-ref-v1.md vocabulary):
  key_source = 'embedded'
  -> Recomputable: yes -- public key ships inside this record, no external fetch.
  -> Anchored: NO -- this key was chosen by whoever produced this checkpoint.
```

## Reproduce

```bash
python3 scripts/generate_log.py artifacts/log.json
python3 scripts/build_checkpoint.py artifacts/log.json artifacts
python3 verifier/verify.py artifacts                      # local checks only
bash scripts/anchor.sh                                     # anchor on Base mainnet
python3 verifier/verify.py artifacts <anchor_tx_hash>       # + on-chain check
```

## This instance

- `signer_type` / `signer_id`: see `artifacts/checkpoint.json`
- `checkpoint_hash`: see `artifacts/checkpoint_hash.json`
- Anchor status: see `artifacts/anchor.json` (once anchored)

## License

MIT — see `LICENSE`.
