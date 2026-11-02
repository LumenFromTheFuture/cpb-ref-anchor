"""Runs the seven negative fixtures under fixtures/negative/ and asserts each
is rejected with its documented reason code — requested by osr21
(coinbase/agentkit#1141) after reviewing this repo's positive-path worked
example. The 7th (coordinated_key_signer_substitution) is a 6th-round
follow-up asking specifically what distinguishes a self-consistent but
substituted identity from a real one.

Same discipline as verify.py: every fixture is recomputed from scratch here,
never trusted from a cached field (a fixture's own signer_record.verification_result
or similar is deliberately never read as ground truth — see
key_substitution, where that field says "pass").

Fail-closed, reason-coded rejection — not a single pass/fail boolean — same
style as argentum-core's own negative conformance vectors
(examples/conformance/action-ref-v1-domain-negative/, near-miss-v1/).

Run:
    python verifier/verify_negative.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.request

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURES = "fixtures/negative"
REGISTRY = "0x49fEcA52bC634a9Ab773226D16619deC547794aa"
RPC = "https://mainnet.base.org"
ANCHORED_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"


class Rejection(Exception):
    def __init__(self, reason_code: str, detail: str):
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def load(path: str):
    with open(path) as f:
        return json.load(f)


def recompute_log_chain(events: list[dict]):
    """Recomputes the chain from scratch. Raises Rejection on the first
    structural break — does not partially trust a prefix."""
    prev = "GENESIS"
    seen_seqs = []
    for ev in events:
        seen_seqs.append(ev["seq"])
        preimage = {"seq": ev["seq"], "event_type": ev["event_type"], "payload": ev["payload"], "prev_event_hash": ev["prev_event_hash"]}
        h = hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()
        if h != ev["event_hash"]:
            raise Rejection("LOG_EVENT_HASH_MISMATCH", f"seq {ev['seq']}: recomputed {h} != declared {ev['event_hash']}")
        if ev["prev_event_hash"] != prev:
            raise Rejection("LOG_CHAIN_BREAK", f"seq {ev['seq']}: prev_event_hash {ev['prev_event_hash']!r} != expected tip {prev!r}")
        prev = h

    if seen_seqs != sorted(seen_seqs):
        raise Rejection("LOG_SEQUENCE_REORDERED", f"seq order {seen_seqs} is not monotonic")
    expected_run = list(range(seen_seqs[0], seen_seqs[0] + len(seen_seqs)))
    if seen_seqs != expected_run:
        raise Rejection("LOG_SEQUENCE_GAP", f"seq values {seen_seqs} are not a contiguous run")

    return prev  # the recomputed tip


def check_key_substitution(base: str):
    checkpoint = load(f"{base}/checkpoint.json")
    checkpoint_hash_doc = load(f"{base}/checkpoint_hash.json")
    signature = load(f"{base}/signature.json")
    signer_record = load(f"{base}/signer_record.json")

    recomputed_hash = hashlib.sha256(rfc8785.dumps(checkpoint)).hexdigest()
    assert recomputed_hash == checkpoint_hash_doc["checkpoint_hash"]

    pub_raw = base64.b64decode(signer_record["signer_id"])
    pub = Ed25519PublicKey.from_public_bytes(pub_raw)
    sig_bytes = bytes.fromhex(signature["signature_hex"])
    checkpoint_hash_bytes = bytes.fromhex(recomputed_hash)
    try:
        pub.verify(sig_bytes, checkpoint_hash_bytes)
    except InvalidSignature:
        # Deliberately NOT reading signer_record["verification_result"] (it
        # says "pass") -- that is exactly the trap this fixture tests for.
        raise Rejection("SIGNATURE_KEY_MISMATCH", "signature does not verify against the claimed signer_id's public key")
    raise AssertionError("fixture is broken: signature unexpectedly verified")


def check_sequence_gap(base: str):
    log_doc = load(f"{base}/log.json")
    recompute_log_chain(log_doc["events"])  # expected to raise LOG_SEQUENCE_GAP
    raise AssertionError("fixture is broken: no gap detected")


def check_sequence_reorder(base: str):
    log_doc = load(f"{base}/log.json")
    recompute_log_chain(log_doc["events"])  # expected to raise LOG_SEQUENCE_REORDERED
    raise AssertionError("fixture is broken: no reorder detected")


def check_wrong_log_root(base: str):
    log_doc = load(f"{base}/log.json")
    checkpoint = load(f"{base}/checkpoint.json")
    checkpoint_hash_doc = load(f"{base}/checkpoint_hash.json")

    real_tip = recompute_log_chain(log_doc["events"])
    recomputed_hash = hashlib.sha256(rfc8785.dumps(checkpoint)).hexdigest()
    assert recomputed_hash == checkpoint_hash_doc["checkpoint_hash"], "fixture internally inconsistent"

    if checkpoint["log_root"] != real_tip:
        raise Rejection("CHECKPOINT_LOG_ROOT_MISMATCH", f"checkpoint.log_root={checkpoint['log_root']} != recomputed tip={real_tip}")
    raise AssertionError("fixture is broken: log_root matched")


def check_anchor_tx_reverted(base: str):
    receipt = load(f"{base}/mock_receipt.json")
    if receipt["status"] != "0x1":
        raise Rejection("ANCHOR_TX_REVERTED", f"receipt.status={receipt['status']}")
    raise AssertionError("fixture is broken: status was 0x1")


def check_anchor_wrong_event(base: str):
    tx_doc = load(f"{base}/real_tx.json")
    expected = load(f"{base}/checkpoint_hash.json")["checkpoint_hash"]

    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx_doc["tx_hash"]]}).encode()
    req = urllib.request.Request(
        RPC, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "checkpoint-producer-binding-verify-negative/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        receipt = json.loads(resp.read())["result"]

    for log in receipt["logs"]:
        if log["address"].lower() == REGISTRY.lower() and log["topics"][0].lower() == ANCHORED_TOPIC0:
            ref_onchain = log["topics"][1][2:]
            if ref_onchain.lower() != expected.lower():
                raise Rejection("ANCHOR_EVENT_MISMATCH", f"on-chain ref {ref_onchain} != expected {expected} (tx is real, expectation is wrong)")
            raise AssertionError("fixture is broken: hash unexpectedly matched")
    raise AssertionError("no Anchored log found in the real tx at all -- fixture setup is wrong")


def check_coordinated_key_signer_substitution(base: str):
    """osr21's 6th-round follow-up: key B, signer_id=B, signed by B --
    everything LOCAL is self-consistent on purpose. First confirms that
    (the point of the fixture: self-consistency alone proves nothing about
    identity), then checks the real already-anchored tx and expects THAT
    to be where it finally breaks."""
    checkpoint = load(f"{base}/checkpoint.json")
    checkpoint_hash_doc = load(f"{base}/checkpoint_hash.json")
    signature = load(f"{base}/signature.json")
    signer_record = load(f"{base}/signer_record.json")
    tx_doc = load(f"{base}/real_tx.json")

    recomputed_hash = hashlib.sha256(rfc8785.dumps(checkpoint)).hexdigest()
    assert recomputed_hash == checkpoint_hash_doc["checkpoint_hash"]

    pub_raw = base64.b64decode(signer_record["signer_id"])
    pub = Ed25519PublicKey.from_public_bytes(pub_raw)
    checkpoint_hash_bytes = bytes.fromhex(recomputed_hash)
    try:
        pub.verify(bytes.fromhex(signature["signature_hex"]), checkpoint_hash_bytes)
    except InvalidSignature:
        raise AssertionError("fixture is broken: signature should verify locally (that's the point)")

    local_checks = {
        "key_source_declared": signer_record.get("key_source") in ("embedded", "published_jwks", "pinned_registry", "cached_prior"),
        "public_key_hash_matches": hashlib.sha256(pub_raw).hexdigest() == signer_record["public_key_hash"],
        "signer_identity_bound": signer_record["signer_id"] == checkpoint["signer_id"],
        "signature_input_bound": hashlib.sha256(checkpoint_hash_bytes).hexdigest() == signer_record["signature_input_hash"],
    }
    if not all(local_checks.values()):
        raise AssertionError(f"fixture is broken: expected all local checks to pass, got {local_checks}")
    print(f"       local checks (all pass, as expected): {local_checks}")

    # Only now check against the REAL already-anchored tx -- this is where
    # a coordinated-but-different checkpoint actually gets caught.
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx_doc["tx_hash"]]}).encode()
    req = urllib.request.Request(
        RPC, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "checkpoint-producer-binding-verify-negative/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        receipt = json.loads(resp.read())["result"]

    for log in receipt["logs"]:
        if log["address"].lower() == REGISTRY.lower() and log["topics"][0].lower() == ANCHORED_TOPIC0:
            ref_onchain = log["topics"][1][2:]
            if ref_onchain.lower() != recomputed_hash.lower():
                raise Rejection("ANCHOR_CHECKPOINT_MISMATCH", f"this checkpoint's hash {recomputed_hash} was never anchored by {tx_doc['tx_hash']} (on-chain ref there is {ref_onchain})")
            raise AssertionError("fixture is broken: hash unexpectedly matched the real anchor")
    raise AssertionError("no Anchored log found in the real tx -- fixture setup is wrong")


CASES = {
    "key_substitution": check_key_substitution,
    "sequence_gap": check_sequence_gap,
    "sequence_reorder": check_sequence_reorder,
    "wrong_log_root": check_wrong_log_root,
    "anchor_tx_reverted": check_anchor_tx_reverted,
    "anchor_wrong_event": check_anchor_wrong_event,
    "coordinated_key_signer_substitution": check_coordinated_key_signer_substitution,
}


def main() -> int:
    all_ok = True
    for name, check_fn in CASES.items():
        base = f"{FIXTURES}/{name}"
        expected = load(f"{base}/EXPECTED.json")
        try:
            check_fn(base)
            print(f"[FAIL] {name}: expected rejection, got none")
            all_ok = False
        except Rejection as r:
            ok = r.reason_code == expected["reason_code"]
            tag = "ok" if ok else "FAIL"
            print(f"[{tag}] {name}: rejected with {r.reason_code!r} ({r.detail})")
            if not ok:
                print(f"       expected reason_code {expected['reason_code']!r}")
                all_ok = False
        except AssertionError as e:
            print(f"[FAIL] {name}: fixture did not exercise the intended break — {e}")
            all_ok = False

    print()
    print("RESULT:", "ALL REJECTED AS EXPECTED" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
