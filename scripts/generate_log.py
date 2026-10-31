"""Synthetic event log with a hash chain (seq + prev_event_hash), per osr21's
point 1 in coinbase/agentkit#1141: "make each event hash bind its sequence
number and previous-event hash."

100% synthetic data. Not derived from, or a replica of, any real agent log.
"""
import hashlib
import json
import sys

import rfc8785

LOG_SCOPE = "worked-example:checkpoint-producer-binding:demo-log-001"

SYNTHETIC_EVENTS = [
    {"event_type": "task.received", "payload": {"task_id": "t-001", "kind": "research"}},
    {"event_type": "task.planned", "payload": {"task_id": "t-001", "steps": 3}},
    {"event_type": "tool.call", "payload": {"tool": "search", "query": "rfc8785 canonicalization"}},
    {"event_type": "tool.result", "payload": {"tool": "search", "result_count": 7}},
    {"event_type": "tool.call", "payload": {"tool": "fetch", "url": "https://example.invalid/doc-1"}},
    {"event_type": "tool.result", "payload": {"tool": "fetch", "status": 200}},
    {"event_type": "task.step_complete", "payload": {"task_id": "t-001", "step": 1}},
    {"event_type": "tool.call", "payload": {"tool": "summarize", "input_tokens": 1842}},
    {"event_type": "tool.result", "payload": {"tool": "summarize", "output_tokens": 310}},
    {"event_type": "task.step_complete", "payload": {"task_id": "t-001", "step": 2}},
    {"event_type": "task.step_complete", "payload": {"task_id": "t-001", "step": 3}},
    {"event_type": "task.completed", "payload": {"task_id": "t-001", "outcome": "ok"}},
]


def event_hash(seq: int, event_type: str, payload: dict, prev_event_hash: str) -> str:
    preimage = {
        "seq": seq,
        "event_type": event_type,
        "payload": payload,
        "prev_event_hash": prev_event_hash,
    }
    canonical = rfc8785.dumps(preimage)
    return hashlib.sha256(canonical).hexdigest()


def build_log():
    log = []
    prev_hash = "GENESIS"
    for i, ev in enumerate(SYNTHETIC_EVENTS, start=1):
        h = event_hash(i, ev["event_type"], ev["payload"], prev_hash)
        entry = {
            "seq": i,
            "event_type": ev["event_type"],
            "payload": ev["payload"],
            "prev_event_hash": prev_hash,
            "event_hash": h,
        }
        log.append(entry)
        prev_hash = h
    return log


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "artifacts/log.json"
    log = build_log()
    with open(out_path, "w") as f:
        json.dump({"log_scope": LOG_SCOPE, "events": log}, f, indent=2)
    print(f"wrote {len(log)} events to {out_path}")
    print("tip (last event_hash):", log[-1]["event_hash"])
