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
import datetime
import hashlib
import json
import sys
import urllib.request

if __package__:
    from .rpc_quorum import recheck_inclusion_multi_rpc
else:
    from rpc_quorum import recheck_inclusion_multi_rpc

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


def classify_outcomes(findings, signer_record, anchor_result):
    """Separate, machine-readable outcomes -- per osr21's point in
    coinbase/agentkit#1141: a caller must not be able to conflate
    checkpoint-integrity with producer authentication by reading a single
    pass/fail. Each outcome is independent; a caller that only checks
    `signature_valid` (or the overall RESULT) is not checking identity.

    Tri-state semantics, per osr21's follow-up in the same thread: False
    means checked and not satisfied; None means not evaluated/unknown (no
    value here implies a check that silently passed). `anchor_finality` is
    a string state for the same reason `anchor_inclusion_verified` is kept
    separate: `anchor_inclusion_verified=True` only means the expected
    on-chain log was found in a receipt with status success -- it says
    nothing about whether that inclusion has reached this chain's actual
    finality condition. Base is an OP-stack rollup: its real finality
    comes from the L1 fault-proof/dispute-game window, not from
    confirmation count. This verifier does not implement that check, so it
    never reports "finalized" -- doing so without checking it would be the
    same kind of overclaim this function exists to prevent."""
    outcomes = {
        "signature_valid": findings["verification_result_recomputed"] == "pass",
        "checkpoint_key_bound": (
            findings["public_key_hash_matches"]
            and findings["signer_identity_bound"]
            and findings["signature_input_bound"]
        ),
        "anchor_inclusion_verified": anchor_result is not None,
        "anchor_finality": "unseen" if anchor_result is None else "included",
    }
    if signer_record.get("key_source") == "pinned_registry":
        # not implemented in this worked example -- no registry resolver wired
        # up yet, so even this key_source can't claim a resolved identity here.
        outcomes["identity_authenticated"] = None  # unknown, not false: resolver absent, not failed
    else:
        # embedded / published_jwks / cached_prior: the key was chosen by
        # whoever produced the checkpoint, not by an independent trust
        # source. No value of signature_valid, checkpoint_key_bound, or
        # anchor_inclusion_verified can change this.
        outcomes["identity_authenticated"] = False
    return outcomes


def _rpc_at(rpc_url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "checkpoint-producer-binding-verify/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())["result"]


def _rpc(method, params):
    return _rpc_at(RPC, method, params)


def rpc_get_receipt(tx_hash):
    return _rpc("eth_getTransactionReceipt", [tx_hash])


def rpc_chain_id():
    return int(_rpc("eth_chainId", []), 16)


def rpc_get_block_hash(block_number):
    """Current canonical block hash at block_number, or None if that height
    no longer resolves at all (distinct from resolving to a different hash)."""
    block = _rpc("eth_getBlockByNumber", [hex(block_number), False])
    return block["hash"] if block else None


def query_chain_point(rpc_url, block_number):
    """Queries a SINGLE RPC endpoint for (chain_id, block_hash) at
    block_number. Used by recheck_inclusion_multi_rpc() to corroborate
    across independently-operated endpoints -- one call to this function
    proves only what that one endpoint reports, the same limit documented
    on recheck_inclusion() itself. Raises on any transport/JSON error; the
    caller (recheck_inclusion_multi_rpc) treats that as a non-qualifying
    response, never as agreement in either direction."""
    chain_id = int(_rpc_at(rpc_url, "eth_chainId", []), 16)
    block = _rpc_at(rpc_url, "eth_getBlockByNumber", [hex(block_number), False])
    return {"chain_id": chain_id, "block_hash": block["hash"] if block else None}


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
        "chain_id": rpc_chain_id(),
        "tx_hash": tx_hash,
        "block": int(receipt["blockNumber"], 16),
        "block_hash": receipt["blockHash"],
        "anchor_submitter": anchor_submitter,
        "tx_from": receipt["from"],
    }


def recheck_inclusion(block_number, recorded_block_hash, recorded_chain_id):
    """Per osr21's point: 'included' is an observation at a specific chain
    point, not a durable guarantee. This re-queries the CURRENT canonical
    chain_id and block hash at block_number and compares them to what was
    recorded at the time of the original observation.

    Returns a dict, not a bare status, so a caller can see WHEN the check
    ran and WHAT it checked, not just the verdict:
        {"status": "included" | "reorged" | "unknown",
         "checked_at": <ISO-8601 UTC timestamp of this call>,
         "chain_id": <chain_id read just now, or recorded_chain_id if unread>,
         "block": block_number}

    status is 'unknown' whenever the comparison itself cannot be trusted --
    not just when the block height no longer resolves, but also when the
    RPC endpoint's chain_id does not match recorded_chain_id. This is
    checked FIRST, before any block_hash comparison runs: nothing confirms
    this endpoint actually speaks for the recorded chain at all, so no
    included/reorged verdict is produced from it -- the function fails to
    'unknown' instead of answering based on an endpoint that was never
    confirmed to be the right one. 'included' is returned only when both
    chain identity and block hash are confirmed fresh, right now; a caller
    must never treat a past 'included' result as still current without
    calling this again -- checked_at exists precisely so that staleness is
    checkable instead of assumed away.

    This function does not impose a staleness policy of its own -- it
    does not decide how old is too old, same as this repo never collapses
    a check it did run into a stronger claim than what it actually
    verified (see anchor_finality above: 'included', never 'finalized',
    because the fault-proof window was never checked). What it guarantees
    is narrower and absolute: the status it returns is never older than
    checked_at, and it is 'unknown' rather than a stale 'included' whenever
    chain identity or the block itself cannot be confirmed at call time.
    It does not run automatically; a caller invokes it later to find out
    whether a prior 'included' result still holds.

    TRUST BOUNDARY (per osr21's follow-up in the same thread, round 13):
    this is trusted-RPC verification. Matching chain_id and block_hash
    from this ONE configured endpoint proves what that endpoint reports --
    it does not independently establish that the endpoint's view is
    canonical. A caller relying on a single RPC is trusting that endpoint
    not to be wrong or dishonest. See recheck_inclusion_multi_rpc() below
    for a stronger mode that corroborates the same comparison across
    several independently-operated endpoints instead of trusting one."""
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    current_chain_id = rpc_chain_id()
    if current_chain_id != recorded_chain_id:
        return {"status": "unknown", "checked_at": checked_at,
                "chain_id": current_chain_id, "block": block_number,
                "reason": f"chain_id mismatch: expected {recorded_chain_id}, RPC reports {current_chain_id}"}
    current_hash = rpc_get_block_hash(block_number)
    if current_hash is None:
        return {"status": "unknown", "checked_at": checked_at,
                "chain_id": current_chain_id, "block": block_number,
                "reason": "block height does not resolve"}
    status = "included" if current_hash.lower() == recorded_block_hash.lower() else "reorged"
    return {"status": status, "checked_at": checked_at,
            "chain_id": current_chain_id, "block": block_number,
            "block_hash": current_hash}


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

    anchor = None
    if tx_hash:
        anchor = verify_anchor(recomputed_hash, tx_hash)
        print()
        print(f"[ok] [TRUSTED-RPC VERIFICATION] on-chain Anchored event confirmed at block {anchor['block']}")
        print(f"     chain_id             : {anchor['chain_id']}")
        print(f"     tx_hash              : {anchor['tx_hash']}")
        print(f"     block_hash           : {anchor['block_hash']}")
        print(f"     checkpoint signer_id : {checkpoint['signer_id']}  (role: who produced/signed the log)")
        print(f"     anchor_submitter     : {anchor['anchor_submitter']}  (role: who paid gas / submitted the anchor tx)")
        print("     -> tracked and verified as SEPARATE roles, per osr21's point 2.")
        print("     -> this is an observation at this chain point, not a durable guarantee --")
        print("        recheck_inclusion(block, block_hash) later re-verifies it still holds.")
        print("     -> labeled TRUSTED-RPC VERIFICATION per osr21's round-13 point: this proves")
        print("        what the configured RPC endpoint reports, not independently that its")
        print("        view is canonical. recheck_inclusion_multi_rpc() corroborates across")
        print("        endpoints with explicitly configured operator IDs instead of trusting one.")
    else:
        print()
        print("[skip] no tx_hash given -- not anchored yet, on-chain check skipped")

    outcomes = classify_outcomes(findings, signer_record, anchor)
    print()
    print("OUTCOMES (read these independently -- do not collapse to one RESULT):")
    for k, v in outcomes.items():
        print(f"  {k}: {v}")
    if outcomes["identity_authenticated"] is False:
        print("  -> identity_authenticated is False regardless of the other three:")
        print("     this signer_record's key_source cannot be resolved against an")
        print("     independent trust source. Only a configured key_source='pinned_registry'")
        print("     binding -- not implemented here -- could change that.")
    if outcomes["anchor_finality"] == "included":
        print("  -> anchor_finality is 'included', never 'finalized', in this verifier:")
        print("     Base's real finality is the L1 fault-proof/dispute-game window, not")
        print("     confirmation count. This verifier only confirmed a success receipt --")
        print("     it does not check that window, so it does not claim finality.")

    print()
    print("RESULT:", "PASS" if all_local_ok else "FAIL")
    return 0 if all_local_ok else 1


if __name__ == "__main__":
    artifacts_dir = sys.argv[1] if len(sys.argv) > 1 else "artifacts"
    tx_hash = sys.argv[2] if len(sys.argv) > 2 else None
    sys.exit(main(artifacts_dir, tx_hash))
