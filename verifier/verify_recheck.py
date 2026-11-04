"""Tests recheck_inclusion() against the real anchor tx used throughout this
repo -- requested by osr21 (coinbase/agentkit#1141, round 11) after the
anchor_finality fix: 'included' is an observation at a specific chain
point, not a durable guarantee, so a caller needs a way to re-verify it
later.

Round 12 (same thread): osr21 asked for three more things, all addressed
here --
  1. record checked_at alongside chain_id and block_hash -- recheck_inclusion()
     now returns a dict carrying all three, not a bare status string.
  2. if canonical block or chain identity cannot be confirmed, return
     'unknown' rather than treating an old inclusion as current -- see the
     new chain-id-mismatch case below, and the docstring on recheck_inclusion().
  3. label the stale-hash case explicitly as simulated/unit coverage,
     separate from live-RPC evidence -- every case below is tagged
     [LIVE-RPC EVIDENCE] (a genuinely observed, unforced chain state) or
     [SIMULATED / UNIT COVERAGE] (a real RPC call, but with a fabricated
     comparison input standing in for a condition -- reorg, wrong network --
     we cannot force to happen on Base mainnet for real).

We cannot force a real reorg, or a real wrong-network RPC endpoint, to test
the negative cases. Every case below makes a real RPC call; only the
comparison input differs between the LIVE-RPC and SIMULATED cases.

Run:
    python verifier/verify_recheck.py
"""
from verify import recheck_inclusion, rpc_chain_id

REAL_ANCHOR_BLOCK = 53311834
REAL_ANCHOR_BLOCK_HASH = "0x2fab867fbeb512526683693bcf64e473056c3e9728d51c420e14a98f275d3ab4"
REAL_ANCHOR_CHAIN_ID = 8453  # Base mainnet


def main():
    # [LIVE-RPC EVIDENCE]: real block, real recorded hash and chain_id,
    # re-queried against the real current chain state. Nothing here is
    # fabricated -- this confirms the check correctly reports "still
    # included" when nothing has changed, and shows checked_at/chain_id
    # on the result.
    result = recheck_inclusion(REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, REAL_ANCHOR_CHAIN_ID)
    assert result["status"] == "included", f"expected included, got {result}"
    assert result["chain_id"] == REAL_ANCHOR_CHAIN_ID
    assert result["checked_at"], "checked_at must be present"
    print(f"[LIVE-RPC EVIDENCE] recheck against the real, current chain state: {result['status']}")
    print(f"                    checked_at={result['checked_at']}  chain_id={result['chain_id']}  block={result['block']}")

    # [SIMULATED / UNIT COVERAGE]: same real block and chain_id, but a
    # fabricated block_hash standing in for "what we'd have recorded if
    # this block had since been reorged out." The RPC call is real; only
    # the comparison input is synthetic.
    fabricated_stale_hash = "0x" + "ab" * 32
    result = recheck_inclusion(REAL_ANCHOR_BLOCK, fabricated_stale_hash, REAL_ANCHOR_CHAIN_ID)
    assert result["status"] == "reorged", f"expected reorged, got {result}"
    print(f"[SIMULATED / UNIT COVERAGE] recheck against a fabricated stale hash: {result['status']}")

    # [SIMULATED / UNIT COVERAGE]: a block height far beyond the current
    # chain tip does not resolve at all -- distinct from resolving to a
    # different hash. The height itself is the synthetic input.
    result = recheck_inclusion(999_999_999_999, fabricated_stale_hash, REAL_ANCHOR_CHAIN_ID)
    assert result["status"] == "unknown", f"expected unknown, got {result}"
    assert "reason" in result
    print(f"[SIMULATED / UNIT COVERAGE] recheck against an unresolvable block height: {result['status']} ({result['reason']})")

    # [SIMULATED / UNIT COVERAGE]: real block and real recorded hash, but a
    # fabricated recorded_chain_id standing in for "the caller's stored
    # record was made against a different network than the RPC endpoint
    # now answers for." Nothing here confirms this endpoint speaks for the
    # recorded chain at all, so no included/reorged verdict should come
    # from it -- this must fail to 'unknown', not produce any comparison.
    wrong_chain_id = REAL_ANCHOR_CHAIN_ID + 1
    result = recheck_inclusion(REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, wrong_chain_id)
    assert result["status"] == "unknown", f"expected unknown, got {result}"
    assert "chain_id mismatch" in result["reason"]
    print(f"[SIMULATED / UNIT COVERAGE] recheck against a mismatched recorded chain_id: {result['status']} ({result['reason']})")

    # Sanity: the live RPC chain_id really is Base mainnet, independent of
    # anything recheck_inclusion() asserts about itself.
    assert rpc_chain_id() == REAL_ANCHOR_CHAIN_ID
    print(f"[LIVE-RPC EVIDENCE] confirmed RPC endpoint chain_id is Base mainnet: {REAL_ANCHOR_CHAIN_ID}")

    print()
    print("RESULT: ALL CASES BEHAVED AS EXPECTED")
    print("(2 LIVE-RPC EVIDENCE cases, 3 SIMULATED / UNIT COVERAGE cases -- see tags above)")


if __name__ == "__main__":
    main()
