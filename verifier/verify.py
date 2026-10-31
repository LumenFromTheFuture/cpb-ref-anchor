"""Independent verifier for the checkpoint worked example.

Recomputes everything from the raw artifacts (never trusts a cached value --
including `signer_record.verification_result`, which is recomputed fresh
here rather than read), verifies the detached signature, checks the
`signer_record` against verifier-key-source-ref-v1's invariants, and -- once
anchored -- re-fetches the on-chain Anchored event directly from a public
Base mainnet RPC. Reports `anchor_submitter` (anchoredBy) as a role distinct
from the checkpoint's `signer_id`, per osr21's explicit point in
coinbase/agentkit#1141: "record the on-chain anchor caller separately as
anchor_submitter -- it may be a relayer, not the log producer."
"""
import base64
import hashlib
import json
import sys
import urllib.request

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

REGISTRY = "0x49fEcA52bC634a9Ab773226D16619deC547794aa".lower()
RPC = "https://mainnet.base.org"
ANCHORED_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"


def load(path):
    with open(path) as f:
        return json.load(f)


def verify_log_chain(log_doc):
    events = log_doc["events"]
    prev = "GENESIS"
    for ev in events:
        assert ev["prev_event_hash"] == prev, f"seq {ev['seq']}: chain break"
        preimage = {
            "seq": ev["seq"],
            "event_type": ev["event_type"],
            "payload": ev["payload"],
            "prev_event_hash": ev["prev_event_hash"],
        }
        h = hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()
        assert h == ev["event_hash"], f"seq {ev['seq']}: event_hash mismatch"
        prev = h
    return events[0]["seq"], events[-1]["seq"], len(events), events[-1]["event_hash"]


def verify_checkpoint(checkpoint, expected_hash):
    recomputed = hashlib.sha256(rfc8785.dumps(checkpoint)).hexdigest()
    assert recomputed == expected_hash, (
        f"checkpoint_hash mismatch: recomputed {recomputed} != declared {expected_hash}"
    )
    return recomputed


def verify_signer_record(checkpoint, checkpoint_hash, signature, signer_record):
    """Checks against verifier-key-source-ref-v1.md's invariants, adapted to
    a single-signer checkpoint (that spec's native context is multi-signer
    admission -- see PROVENANCE.md)."""
    findings = {}

    # invariant: key_source_declared
    findings["key_source_declared"] = signer_record.get("key_source") in (
        "embedded",
        "published_jwks",
        "pinned_registry",
        "cached_prior",
    )

    pub_raw = base64.b64decode(signer_record["signer_id"])
    recomputed_pkh = hashlib.sha256(pub_raw).hexdigest()
    findings["public_key_hash_matches"] = recomputed_pkh == signer_record["public_key_hash"]

    # invariant: signer_identity_bound -- signer_id in signer_record must
    # equal signer_id in the checkpoint preimage it attests to.
    findings["signer_identity_bound"] = signer_record["signer_id"] == checkpoint["signer_id"]

    # invariant: signature_input_bound -- recompute what was actually signed
    checkpoint_hash_bytes = bytes.fromhex(checkpoint_hash)
    recomputed_sig_input_hash = hashlib.sha256(checkpoint_hash_bytes).hexdigest()
    findings["signature_input_bound"] = (
        recomputed_sig_input_hash == signer_record["signature_input_hash"]
    )

    # cryptographic check, independent of verification_result stored in the artifact
    pub = Ed25519PublicKey.from_public_bytes(pub_raw)
    try:
        pub.verify(bytes.fromhex(signature["signature_hex"]), checkpoint_hash_bytes)
        crypto_ok = True
    except InvalidSignature:
        crypto_ok = False
    findings["verification_result_recomputed"] = "pass" if crypto_ok else "fail"
    findings["verification_result_matches_stored"] = (
        findings["verification_result_recomputed"] == signer_record.get("verification_result")
    )

    return findings


def rpc_get_receipt(tx_hash):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx_hash]}
    ).encode()
    req = urllib.request.Request(
        RPC,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "checkpoint-producer-binding-verify/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())["result"]


def verify_anchor(checkpoint_hash, tx_hash):
    receipt = rpc_get_receipt(tx_hash)
    assert receipt is not None, "tx not found on mainnet.base.org"
    assert receipt["status"] == "0x1", "tx reverted"
    matched = None
    for log in receipt["logs"]:
        if log["address"].lower() == REGISTRY and log["topics"][0].lower() == ANCHORED_TOPIC0:
            matched = log
            break
    assert matched is not None, "no Anchored log from the expected registry"
    ref_onchain = matched["topics"][1][2:]
    assert ref_onchain.lower() == checkpoint_hash.lower(), "on-chain ref != checkpoint_hash"
    anchor_submitter = "0x" + matched["topics"][2][-40:]
    return {
        "block": int(receipt["blockNumber"], 16),
        "anchor_submitter": anchor_submitter,
        "tx_from": receipt["from"],
    }


def main(artifacts_dir="artifacts", tx_hash=None):
    log_doc = load(f"{artifacts_dir}/log.json")
    checkpoint = load(f"{artifacts_dir}/checkpoint.json")
    checkpoint_hash_doc = load(f"{artifacts_dir}/checkpoint_hash.json")
    signature = load(f"{artifacts_dir}/signature.json")
    signer_record = load(f"{artifacts_dir}/signer_record.json")

    first_seq, last_seq, count, tip = verify_log_chain(log_doc)
    print(f"[ok] log hash chain verified: {count} events, seq {first_seq}..{last_seq}")
    assert checkpoint["first_seq"] == first_seq
    assert checkpoint["last_seq"] == last_seq
    assert checkpoint["event_count"] == count
    assert checkpoint["log_root"] == tip
    print("[ok] checkpoint fields match recomputed log chain")

    recomputed_hash = verify_checkpoint(checkpoint, checkpoint_hash_doc["checkpoint_hash"])
    print(f"[ok] checkpoint_hash recomputed independently: {recomputed_hash}")
    print(f"     signer_type={checkpoint['signer_type']} (signing-trust-ref.md vocabulary)")

    findings = verify_signer_record(checkpoint, recomputed_hash, signature, signer_record)
    for k, v in findings.items():
        tag = "ok" if v in (True, "pass") else "FAIL"
        print(f"[{tag}] {k}: {v}")

    print()
    print("GUARANTEE TYPE (verifier-key-source-ref-v1.md vocabulary):")
    print(f"  key_source = {signer_record['key_source']!r}")
    print("  -> Recomputable: yes -- public key ships inside this record, no external fetch.")
    print("  -> Anchored: NO -- this key was chosen by whoever produced this checkpoint.")
    print("     Per verifier-key-source-ref-v1.md's own invariant 6")
    print("     (recomputable_not_anchored): recomputability must never be reported as")
    print("     authentication. A real deployment wanting an anchored guarantee would use")
    print("     key_source='pinned_registry' against an independent registry instead.")

    all_local_ok = all(v in (True, "pass") for v in findings.values())

    if tx_hash:
        anchor = verify_anchor(recomputed_hash, tx_hash)
        print()
        print(f"[ok] on-chain Anchored event confirmed at block {anchor['block']}")
        print(f"     checkpoint signer_id : {checkpoint['signer_id']}  (role: who produced/signed the log)")
        print(f"     anchor_submitter     : {anchor['anchor_submitter']}  (role: who paid gas / submitted the anchor tx)")
        print("     -> tracked and verified as SEPARATE roles, per osr21's point 2.")
    else:
        print()
        print("[skip] no tx_hash given -- not anchored yet, on-chain check skipped")

    print()
    print("RESULT:", "PASS" if all_local_ok else "FAIL")
    return 0 if all_local_ok else 1


if __name__ == "__main__":
    artifacts_dir = sys.argv[1] if len(sys.argv) > 1 else "artifacts"
    tx_hash = sys.argv[2] if len(sys.argv) > 2 else None
    sys.exit(main(artifacts_dir, tx_hash))
