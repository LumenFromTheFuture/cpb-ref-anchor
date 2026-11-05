"""Tests recheck_inclusion_multi_rpc() -- requested by osr21
(coinbase/agentkit#1141, round 13) after the chain_id-guard fix: matching
chain_id and block_hash from a single RPC endpoint proves what that
endpoint reports, not independently that its view is canonical. This
stronger assurance mode corroborates the same comparison across several
independently-operated endpoints instead of trusting one, per osr21's
explicit ask: "if there's disagreement or unverifiable data, the result
should remain unknown," plus a fixture modeling "a consistently dishonest
endpoint that reports the expected chain ID but a fabricated block view."

Every [LIVE-RPC EVIDENCE] case below makes real RPC calls to real,
independently-operated Base mainnet endpoints (mainnet.base.org -- the
Base protocol team's own node -- and base.drpc.org -- dRPC, a distinct
operator; both were cross-checked against five more public endpoints
(base.publicnode.com, base-rpc.publicnode.com, 1rpc.io/base,
base-mainnet.public.blastapi.io, base.gateway.tenderly.co) before writing
this file -- all seven agreed on REAL_ANCHOR_BLOCK_HASH. An eighth
endpoint tried (endpoints.omniatech.io) errored and was excluded, not
counted toward either side, same discipline this file's own
recheck_inclusion_multi_rpc() applies to an unreachable endpoint.
[SIMULATED / UNIT COVERAGE] cases cannot be produced by real endpoints on
demand (we cannot make Base mainnet reorg, nor make a real operator lie,
nor make a real endpoint go offline on a schedule) -- those substitute a
fabricated query_fn standing in for the condition, same discipline as
verify_recheck.py's single-RPC tests: label the substitution, never let
it pass as live evidence.

Run:
    python verifier/verify_recheck_multi.py
"""
from verify import recheck_inclusion_multi_rpc, query_chain_point

REAL_ANCHOR_BLOCK = 53311834
REAL_ANCHOR_BLOCK_HASH = "0x2fab867fbeb512526683693bcf64e473056c3e9728d51c420e14a98f275d3ab4"
REAL_ANCHOR_CHAIN_ID = 8453  # Base mainnet

# Two real, independently-operated public Base mainnet RPC endpoints.
# Verified by hand (curl, outside this test) to agree with each other and
# with mainnet.base.org on REAL_ANCHOR_BLOCK_HASH before being wired in here.
REAL_ENDPOINT_A = "https://mainnet.base.org"       # Base protocol team
REAL_ENDPOINT_B = "https://base.drpc.org"          # dRPC -- distinct operator


def real(rpc_url):
    return lambda block_number: query_chain_point(rpc_url, block_number)


def fixed(chain_id, block_hash):
    """A fabricated endpoint: returns a constant answer, no network call.
    Used only to stand in for conditions a real endpoint can't be made to
    exhibit on demand (lying, disagreeing, being offline)."""
    return lambda block_number: {"chain_id": chain_id, "block_hash": block_hash}


def unreachable():
    def fn(block_number):
        raise TimeoutError("simulated: endpoint did not respond")
    return fn


def main():
    # [LIVE-RPC EVIDENCE]: two real, independently-operated endpoints,
    # queried separately, both asked about the real anchor block. Nothing
    # fabricated here -- confirms the corroboration logic reports
    # "included" with endpoints_qualifying=2 when both genuinely agree.
    result = recheck_inclusion_multi_rpc(
        REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, REAL_ANCHOR_CHAIN_ID,
        endpoints=[("mainnet.base.org", real(REAL_ENDPOINT_A)),
                   ("base.drpc.org", real(REAL_ENDPOINT_B))],
    )
    assert result["status"] == "included", f"expected included, got {result}"
    assert result["endpoints_qualifying"] == 2
    assert result["checked_at"]
    print(f"[LIVE-RPC EVIDENCE] two independently-operated endpoints agree: {result['status']}")
    print(f"                    endpoints_qualifying={result['endpoints_qualifying']}/{result['endpoints_queried']}"
          f"  checked_at={result['checked_at']}")

    # [SIMULATED / UNIT COVERAGE]: osr21's exact fixture request -- "a
    # consistently dishonest endpoint that reports the expected chain ID
    # but a fabricated block view." Paired with ONE real, honest endpoint.
    # The dishonest endpoint cannot force a false "included" (it disagrees
    # with the honest one, so they never reach agreement) and cannot force
    # a false "reorged" either (nothing here resolves the disagreement in
    # the dishonest endpoint's favor) -- must land on "unknown".
    fabricated_block_view = "0x" + "66" * 32
    dishonest = fixed(REAL_ANCHOR_CHAIN_ID, fabricated_block_view)
    result = recheck_inclusion_multi_rpc(
        REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, REAL_ANCHOR_CHAIN_ID,
        endpoints=[("mainnet.base.org (honest)", real(REAL_ENDPOINT_A)),
                   ("fabricated-liar (dishonest)", dishonest)],
    )
    assert result["status"] == "unknown", f"expected unknown, got {result}"
    assert result["endpoints_qualifying"] == 2  # both qualify (right chain_id, a hash) -- they just disagree
    assert "disagree" in result["reason"]
    print(f"[SIMULATED / UNIT COVERAGE] one honest + one dishonest (correct chain_id, "
          f"fabricated block view): {result['status']} ({result['reason']})")

    # [SIMULATED / UNIT COVERAGE]: insufficient corroboration. Only ONE
    # endpoint qualifies (even though it happens to be correct) -- below
    # min_endpoints=2, so this must still be "unknown". A single endpoint,
    # however accurate, is exactly the trust boundary this function exists
    # to raise the bar past.
    result = recheck_inclusion_multi_rpc(
        REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, REAL_ANCHOR_CHAIN_ID,
        endpoints=[("mainnet.base.org (alone)", real(REAL_ENDPOINT_A))],
    )
    assert result["status"] == "unknown", f"expected unknown, got {result}"
    assert "need >=" in result["reason"]
    print(f"[SIMULATED / UNIT COVERAGE] single correct endpoint, below quorum: "
          f"{result['status']} ({result['reason']})")

    # [SIMULATED / UNIT COVERAGE]: one real endpoint + one that reports the
    # WRONG chain_id (a different network's RPC answering under this URL,
    # or misconfiguration) + one real endpoint again. The wrong-chain_id
    # endpoint is excluded from the count entirely -- not a disagreeing
    # vote, just absent -- so this still needs a second qualifying
    # endpoint to reach the "included" verdict.
    wrong_chain = fixed(REAL_ANCHOR_CHAIN_ID + 1, REAL_ANCHOR_BLOCK_HASH)
    result = recheck_inclusion_multi_rpc(
        REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, REAL_ANCHOR_CHAIN_ID,
        endpoints=[("mainnet.base.org", real(REAL_ENDPOINT_A)),
                   ("wrong-network", wrong_chain)],
    )
    assert result["status"] == "unknown", f"expected unknown, got {result}"
    assert result["endpoints_qualifying"] == 1  # only the real endpoint qualifies
    print(f"[SIMULATED / UNIT COVERAGE] one real endpoint + one reporting the wrong "
          f"chain_id: {result['status']} ({result['reason']})")

    # [SIMULATED / UNIT COVERAGE]: an unreachable endpoint (timeout/error)
    # paired with one real endpoint -- the error is excluded, not treated
    # as disagreement or as a missing vote that still happens to pass;
    # same "need >= min_endpoints" floor as the single-endpoint case.
    result = recheck_inclusion_multi_rpc(
        REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, REAL_ANCHOR_CHAIN_ID,
        endpoints=[("mainnet.base.org", real(REAL_ENDPOINT_A)),
                   ("down-endpoint", unreachable())],
    )
    assert result["status"] == "unknown", f"expected unknown, got {result}"
    assert result["endpoints_qualifying"] == 1
    print(f"[SIMULATED / UNIT COVERAGE] one real endpoint + one unreachable: "
          f"{result['status']} ({result['reason']})")

    # [SIMULATED / UNIT COVERAGE]: two endpoints that agree with EACH OTHER
    # on a hash different from recorded_block_hash (the only way to exhibit
    # a real reorg through this function's logic -- we cannot force Base
    # mainnet to reorg, so both endpoints are fabricated for this one case
    # only, in deliberate agreement with each other). Confirms "reorged" is
    # reachable, and distinct from "unknown": corroborated disagreement
    # with the RECORDED hash is a verdict, uncorroborated disagreement
    # BETWEEN endpoints (the dishonest-endpoint case above) is not.
    reorged_hash = "0x" + "77" * 32
    result = recheck_inclusion_multi_rpc(
        REAL_ANCHOR_BLOCK, REAL_ANCHOR_BLOCK_HASH, REAL_ANCHOR_CHAIN_ID,
        endpoints=[("simulated-A-post-reorg", fixed(REAL_ANCHOR_CHAIN_ID, reorged_hash)),
                   ("simulated-B-post-reorg", fixed(REAL_ANCHOR_CHAIN_ID, reorged_hash))],
    )
    assert result["status"] == "reorged", f"expected reorged, got {result}"
    assert result["endpoints_qualifying"] == 2
    print(f"[SIMULATED / UNIT COVERAGE] two endpoints agreeing on a hash different "
          f"from recorded (fabricated -- cannot force a real Base reorg): {result['status']}")

    print()
    print("RESULT: ALL CASES BEHAVED AS EXPECTED")
    print("(1 LIVE-RPC EVIDENCE case, 5 SIMULATED / UNIT COVERAGE cases -- see tags above)")


if __name__ == "__main__":
    main()
