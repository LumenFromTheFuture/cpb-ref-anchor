"""Tests recheck_inclusion() against the real anchor tx used throughout this
repo — requested by osr21 (coinbase/agentkit#1141, round 11) after the
anchor_finality fix: 'included' is an observation at a specific chain
point, not a durable guarantee, so a caller needs a way to re-verify it
later.

We cannot force a real reorg on Base mainnet to test the negative case.
The positive case re-queries the real, current chain state (no synthetic
data). The negative case feeds recheck_inclusion() a deliberately wrong,
fabricated block_hash to simulate what a reorg would look like -- this is
explicitly a synthetic input to a real check, not a fabricated result.

Run:
    python verifier/verify_recheck.py
"""
from verify import recheck_inclusion

REAL_ANCHOR_BLOCK = 53311834
REAL_ANCHOR_BLOCK_HASH = "0x2fab867fbeb512526683693bcf64e473056c3e9728d51c420e14a98f275d3ab4"


def main():
    # Positive case: real block, real recorded hash, re-queried against the
    # real current chain state (no reorg has occurred -- this just confirms
    # the check correctly reports "still included" when nothing changed).
    result = recheck_inclusion(REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH)
    assert result == "included", f"expected included, got {result}"
    print(f"[ok] recheck against the real, current chain state: {result}")

    # Negative case: same real block, but a fabricated block_hash standing
    # in for "what we'd have recorded if this block had since been
    # reorged out." The RPC call is real; only the comparison input is
    # synthetic.
    fabricated_stale_hash = "0x" + "ab" * 32
    result = recheck_inclusion(REAL_ANCHOR_BLOCK, fabricated_stale_hash)
    assert result == "reorged", f"expected reorged, got {result}"
    print(f"[ok] recheck against a fabricated stale hash: {result}")

    # Edge case: a block height far beyond the current chain tip does not
    # resolve at all -- distinct from resolving to a different hash.
    result = recheck_inclusion(999_999_999_999, fabricated_stale_hash)
    assert result == "unknown", f"expected unknown, got {result}"
    print(f"[ok] recheck against an unresolvable block height: {result}")

    print()
    print("RESULT: ALL CASES BEHAVED AS EXPECTED")


if __name__ == "__main__":
    main()
