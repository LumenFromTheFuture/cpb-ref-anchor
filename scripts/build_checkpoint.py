"""Builds the checkpoint per osr21's design (coinbase/agentkit#1141, points 1-3),
using argentum-core's OWN pre-existing vocabulary where it already applies,
rather than inventing parallel field names:

- `signer_type` / `signer_id` come from docs/spec/signing-trust-ref.md
  (first commit 84de0e3, 2026-06-21) -- NOT a new "producer_id" field.
  Note: we reuse the *field vocabulary*, embedded inside a new checkpoint
  preimage shape. We do not compute a separate signing_trust_ref hash --
  that primitive binds to a single action_ref, and a checkpoint spans many
  actions (first_seq..last_seq), so there is no single action_ref for it
  to bind to here.
- The key-source / key-manifest artifact follows the `signer_record` schema
  from docs/spec/verifier-key-source-ref-v1.md (first commit 7dbef87,
  2026-06-28) -- all 8 required fields, adapted to a single-signer case
  (that spec's native context is multi-signer admission; see PROVENANCE.md
  for the honest adaptation notes).
- Detached Ed25519 signature stays OUTSIDE the preimage (osr21's explicit
  instruction, to avoid circularity).
- `log_root` / `first_seq` / `last_seq` / `event_count` /
  `previous_checkpoint_root` are genuinely new -- argentum-core had no
  append-only-log-checkpoint primitive before this.

The Ed25519 key generated here is a throwaway sample key with no real-world
value, used only to demonstrate the pattern -- see PROVENANCE.md.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

DOMAIN = "MYCELIUM-CHECKPOINT-V1"
SIGNER_TYPE = "agent_keypair"  # per signing-trust-ref.md: key controlled by the
                                # agent instance, not the operator


def main(log_path, out_dir):
    with open(log_path) as f:
        log_doc = json.load(f)
    events = log_doc["events"]
    log_scope = log_doc["log_scope"]

    # 1. keygen (throwaway sample key, no real value)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # signing-trust-ref.md: "agent_keypair: EVM address (0x...) or Ed25519
    # public key (base64)" -- we have no EVM address for this key, so
    # signer_id is the Ed25519 public key, base64.
    import base64
    signer_id = base64.b64encode(pub_raw).decode()
    key_id = "checkpoint-signing-key-01"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # 2. checkpoint preimage
    preimage = {
        "domain": DOMAIN,
        "log_scope": log_scope,
        "first_seq": events[0]["seq"],
        "last_seq": events[-1]["seq"],
        "event_count": len(events),
        "log_root": events[-1]["event_hash"],
        "previous_checkpoint_root": None,
        "signer_type": SIGNER_TYPE,
        "signer_id": signer_id,
    }
    checkpoint_hash = hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()
    checkpoint_hash_bytes = bytes.fromhex(checkpoint_hash)

    # 3. detached signature over checkpoint_hash -- NOT inside the preimage
    sig = priv.sign(checkpoint_hash_bytes)

    # 4. signer_record per verifier-key-source-ref-v1.md -- all 8 required
    #    fields. key_source = "embedded": the public key ships inside this
    #    record itself, no external fetch needed to recompute the check.
    #    (A real deployment could instead use "pinned_registry" -- see
    #    PROVENANCE.md.)
    signature_input_hash = hashlib.sha256(checkpoint_hash_bytes).hexdigest()
    public_key_hash = hashlib.sha256(pub_raw).hexdigest()

    signer_record = {
        "signer_id": signer_id,
        "key_id": key_id,
        "key_source": "embedded",
        "public_key_hash": public_key_hash,
        "signature_input_hash": signature_input_hash,
        "verification_result": "pass",  # as produced; verify.py recomputes
                                          # this independently and never
                                          # trusts this stored value.
        "key_resolution_time": now,
        "key_resolution_evidence_hash": None,  # not required when
                                                 # key_source == embedded
        # non-normative, carried for reproducibility:
        "public_key_hex": pub_raw.hex(),
    }

    # --- persist ---
    with open(f"{out_dir}/checkpoint.json", "w") as f:
        json.dump(preimage, f, indent=2)

    with open(f"{out_dir}/checkpoint_hash.json", "w") as f:
        json.dump(
            {
                "checkpoint_hash": checkpoint_hash,
                "anchor_ref_bytes32": "0x" + checkpoint_hash,
                "digest_method": "SHA-256 over RFC 8785 JCS canonical form of checkpoint.json",
            },
            f,
            indent=2,
        )

    with open(f"{out_dir}/signature.json", "w") as f:
        json.dump(
            {
                "checkpoint_hash": checkpoint_hash,
                "signature_algo": "Ed25519",
                "signature_hex": sig.hex(),
                "signer_id": signer_id,
                "note": "detached signature over raw checkpoint_hash bytes; signature itself is NOT part of the hashed preimage (avoids circularity, per osr21's explicit instruction)",
            },
            f,
            indent=2,
        )

    with open(f"{out_dir}/signer_record.json", "w") as f:
        json.dump(signer_record, f, indent=2)

    # private key kept only for this run's reproducibility, clearly marked
    # as a throwaway sample (never a real credential).
    with open(f"{out_dir}/sample_private_key_DO_NOT_USE.hex", "w") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ).hex()
        )

    print("signer_type:", SIGNER_TYPE)
    print("signer_id:", signer_id)
    print("checkpoint_hash:", checkpoint_hash)
    print("log_root (tip):", preimage["log_root"])


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "artifacts/log.json"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "artifacts"
    main(log_path, out_dir)
