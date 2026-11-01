"""Generates fixtures/negative/<case>/ — deliberately broken artifact sets
requested by osr21 (coinbase/agentkit#1141) after reviewing the positive-path
worked example in this repo.

Mirrors argentum-core's own negative conformance vectors (e.g.
docs/spec/examples/conformance/action-ref-v1-domain-negative/,
examples/conformance/near-miss-v1/): each case is a real, inspectable
artifact set with a byte-exact expected rejection reason code, not a single
pass/fail boolean. verifier/verify_negative.py recomputes each case from
scratch and asserts the expected reason code fires.

Six cases cover osr21's four requested classes (two of the four split into
two reason codes each, since "gaps / reordering" and "reverted / wrong
event" are structurally distinct failures that deserve distinct codes):

  key_substitution     -- SIGNATURE_KEY_MISMATCH
  sequence_gap         -- LOG_SEQUENCE_GAP
  sequence_reorder     -- LOG_SEQUENCE_REORDERED
  wrong_log_root        -- CHECKPOINT_LOG_ROOT_MISMATCH
  anchor_tx_reverted    -- ANCHOR_TX_REVERTED
  anchor_wrong_event    -- ANCHOR_EVENT_MISMATCH

Run:
    python scripts/generate_negative_fixtures.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = "fixtures/negative"
DOMAIN = "MYCELIUM-CHECKPOINT-V1"

# the real, already-anchored positive-path artifacts (artifacts/anchor.json,
# artifacts/checkpoint_hash.json in this repo) -- reused, never re-anchored.
REAL_ANCHOR_TX = "0x1dbff7b7b183b9cf3496646fa4aac52b3267bcfd3982f40847e268ec05f8fbb4"
REAL_CHECKPOINT_HASH = "392cfd89073e0efc7d8ce256444ce53e881b5864a67943c7fe9f6150525f97c8"
REGISTRY = "0x49fEcA52bC634a9Ab773226D16619deC547794aa"


def jcs(obj: dict) -> bytes:
    return rfc8785.dumps(obj)


def mk_log(events: list[dict]) -> dict:
    return {"log_scope": "mycelium-checkpoint-negative-fixture", "events": events}


def event(seq: int, prev: str, event_type: str = "tool.call", payload: str = "demo") -> dict:
    preimage = {"seq": seq, "event_type": event_type, "payload": payload, "prev_event_hash": prev}
    h = hashlib.sha256(jcs(preimage)).hexdigest()
    return {**preimage, "event_hash": h}


def build_clean_chain(n: int = 6) -> list[dict]:
    return build_chain_with_seqs(list(range(1, n + 1)))


def build_chain_with_seqs(seq_labels: list[int]) -> list[dict]:
    """Builds a hash chain honestly from scratch using the given seq LABELS
    in array order. prev_event_hash always points to the true positional
    predecessor's real hash -- the chain linkage is correct regardless of
    what the seq labels say. This is what makes it possible to isolate a
    pure seq-gap or seq-reorder: the hash chain is NOT broken, only the
    claimed numbering is irregular."""
    events = []
    prev = "GENESIS"
    for seq in seq_labels:
        e = event(seq, prev)
        events.append(e)
        prev = e["event_hash"]
    return events


def write(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


# --- 1. key_substitution: signer_id/signer_record both claim key A, but the
#        signature was produced by a DIFFERENT key (B). Everything about the
#        record is internally self-consistent except the one thing that
#        actually matters: the signature does not verify against the
#        claimed key. ---
def gen_key_substitution():
    priv_a = Ed25519PrivateKey.generate()
    pub_a_raw = priv_a.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    priv_b = Ed25519PrivateKey.generate()  # the ACTUAL signer, never declared anywhere

    events = build_clean_chain(6)
    signer_id_a = base64.b64encode(pub_a_raw).decode()

    preimage = {
        "domain": DOMAIN,
        "log_scope": "mycelium-checkpoint-negative-fixture",
        "first_seq": events[0]["seq"],
        "last_seq": events[-1]["seq"],
        "event_count": len(events),
        "log_root": events[-1]["event_hash"],
        "previous_checkpoint_root": None,
        "signer_type": "agent_keypair",
        "signer_id": signer_id_a,
    }
    checkpoint_hash = hashlib.sha256(jcs(preimage)).hexdigest()
    checkpoint_hash_bytes = bytes.fromhex(checkpoint_hash)

    # signed by B, not A -- the substitution
    sig = priv_b.sign(checkpoint_hash_bytes)

    signer_record = {
        "signer_id": signer_id_a,  # still claims A
        "key_id": "checkpoint-signing-key-01",
        "key_source": "embedded",
        "public_key_hash": hashlib.sha256(pub_a_raw).hexdigest(),
        "signature_input_hash": hashlib.sha256(checkpoint_hash_bytes).hexdigest(),
        "verification_result": "pass",  # what a non-recomputing verifier would wrongly trust
        "key_resolution_time": "2026-11-01T00:00:00.000Z",
        "key_resolution_evidence_hash": None,
        "public_key_hex": pub_a_raw.hex(),
    }

    base = f"{OUT}/key_substitution"
    write(f"{base}/log.json", mk_log(events))
    write(f"{base}/checkpoint.json", preimage)
    write(f"{base}/checkpoint_hash.json", {"checkpoint_hash": checkpoint_hash, "anchor_ref_bytes32": "0x" + checkpoint_hash})
    write(f"{base}/signature.json", {"checkpoint_hash": checkpoint_hash, "signature_algo": "Ed25519", "signature_hex": sig.hex(), "signer_id": signer_id_a})
    write(f"{base}/signer_record.json", signer_record)
    write(f"{base}/EXPECTED.json", {"expected_result": "REJECT", "reason_code": "SIGNATURE_KEY_MISMATCH"})
    print("key_substitution:", checkpoint_hash)


# --- 2. sequence_gap: a FULLY hash-valid chain (prev_event_hash correctly
#        points to each true positional predecessor) whose seq LABELS have
#        a gap (1,2,3,5,6 -- seq 4 was never assigned to anything, even
#        though the chain itself is unbroken). Isolates "events are missing
#        from the numbering" from "the chain was tampered with". ---
def gen_sequence_gap():
    events = build_chain_with_seqs([1, 2, 3, 5, 6])
    base = f"{OUT}/sequence_gap"
    write(f"{base}/log.json", mk_log(events))
    write(f"{base}/EXPECTED.json", {"expected_result": "REJECT", "reason_code": "LOG_SEQUENCE_GAP"})
    print("sequence_gap: seq labels", [e["seq"] for e in events], "-- chain itself is hash-valid")


# --- 3. sequence_reorder: a FULLY hash-valid chain (same positional
#        prev_event_hash guarantee as above) whose seq LABELS are not
#        monotonic (1,2,4,3,5,6 -- seq 4 is claimed before seq 3). Isolates
#        "the claimed numbering goes backwards" from "the chain was
#        tampered with": every hash link, walked in the order given, is
#        still genuinely correct. ---
def gen_sequence_reorder():
    events = build_chain_with_seqs([1, 2, 4, 3, 5, 6])
    base = f"{OUT}/sequence_reorder"
    write(f"{base}/log.json", mk_log(events))
    write(f"{base}/EXPECTED.json", {"expected_result": "REJECT", "reason_code": "LOG_SEQUENCE_REORDERED"})
    print("sequence_reorder: seq labels", [e["seq"] for e in events], "-- chain itself is hash-valid")


# --- 4. wrong_log_root: checkpoint declares a log_root that does not match
#        the actual tip of the log it claims to summarize (points at an
#        earlier event instead of the real tip -- a stale/substituted root). ---
def gen_wrong_log_root():
    events = build_clean_chain(6)
    wrong_root = events[3]["event_hash"]  # seq 4's hash, not seq 6's (the real tip)

    pub_raw = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    preimage = {
        "domain": DOMAIN,
        "log_scope": "mycelium-checkpoint-negative-fixture",
        "first_seq": events[0]["seq"],
        "last_seq": events[-1]["seq"],
        "event_count": len(events),
        "log_root": wrong_root,
        "previous_checkpoint_root": None,
        "signer_type": "agent_keypair",
        "signer_id": base64.b64encode(pub_raw).decode(),
    }
    checkpoint_hash = hashlib.sha256(jcs(preimage)).hexdigest()

    base = f"{OUT}/wrong_log_root"
    write(f"{base}/log.json", mk_log(events))
    write(f"{base}/checkpoint.json", preimage)
    write(f"{base}/checkpoint_hash.json", {"checkpoint_hash": checkpoint_hash, "anchor_ref_bytes32": "0x" + checkpoint_hash})
    write(f"{base}/EXPECTED.json", {"expected_result": "REJECT", "reason_code": "CHECKPOINT_LOG_ROOT_MISMATCH"})
    print("wrong_log_root: checkpoint.log_root =", wrong_root, "real tip =", events[-1]["event_hash"])


# --- 5. anchor_tx_reverted: a SYNTHETIC captured receipt (status: "0x0").
#        Labeled explicitly as synthetic -- nothing was broadcast to revert
#        on purpose; this is a fixture, not a live call, same posture as
#        log.json's own "100% synthetic" labeling in the positive example. ---
def gen_anchor_tx_reverted():
    synthetic_receipt = {
        "_fixture_note": "SYNTHETIC -- captured shape only, not a real broadcast tx. "
                          "No transaction was deliberately reverted to produce this; "
                          "it exists only to exercise verify_negative.py's own rejection logic.",
        "status": "0x0",
        "blockNumber": "0x32dba1a",
        "from": "0xdcc84e9798e8eb1b1b48a31b8f35e5aa7b83dbf4",
        "logs": [],
    }
    base = f"{OUT}/anchor_tx_reverted"
    write(f"{base}/mock_receipt.json", synthetic_receipt)
    write(f"{base}/checkpoint_hash.json", {"checkpoint_hash": REAL_CHECKPOINT_HASH})
    write(f"{base}/EXPECTED.json", {"expected_result": "REJECT", "reason_code": "ANCHOR_TX_REVERTED"})
    print("anchor_tx_reverted: synthetic receipt, status=0x0")


# --- 6. anchor_wrong_event: reuses the REAL anchor tx from this repo's
#        positive path (0x1dbff7b7...) -- a real, successful, on-chain
#        Anchored event -- but checks it against a checkpoint_hash that is
#        NOT the one that tx actually anchored. The chain data is real; the
#        break is a mismatched expectation, which is exactly osr21's "log of
#        an event that is not the Anchored final [for this claim]" case. ---
def gen_anchor_wrong_event():
    wrong_hash = hashlib.sha256(b"not the hash this tx actually anchored").hexdigest()
    base = f"{OUT}/anchor_wrong_event"
    write(f"{base}/real_tx.json", {"tx_hash": REAL_ANCHOR_TX, "note": "real tx from artifacts/anchor.json in this repo's positive path"})
    write(f"{base}/checkpoint_hash.json", {"checkpoint_hash": wrong_hash})
    write(f"{base}/EXPECTED.json", {"expected_result": "REJECT", "reason_code": "ANCHOR_EVENT_MISMATCH"})
    print("anchor_wrong_event: real tx", REAL_ANCHOR_TX, "checked against wrong hash", wrong_hash)


if __name__ == "__main__":
    gen_key_substitution()
    gen_sequence_gap()
    gen_sequence_reorder()
    gen_wrong_log_root()
    gen_anchor_tx_reverted()
    gen_anchor_wrong_event()
