"""
Phase 3: Runtime Anomaly Detection (Execution State)

Reads Falco JSON-line alerts (Falco itself taps eBPF/syscall events; this
module consumes its output rather than re-implementing eBPF probes).
Builds a simple frequency-based baseline per container and flags deviations
using an Isolation Forest, so unusual behavior is caught without hand-written
signatures.

In production, point FALCO_LOG_PATH at Falco's file/http output, or replace
`read_events` with a socket/HTTP listener for real-time streaming.
"""

import json
import os
import time
from collections import defaultdict, Counter

import numpy as np
from sklearn.ensemble import IsolationForest

from config import FALCO_LOG_PATH

# Rule names that are always treated as critical regardless of the ML baseline
HIGH_PRIORITY_RULES = {
    "Terminal shell in container",
    "Write below etc",
    "Write below binary dir",
    "Unexpected outbound connection",
}


def read_events(log_path=FALCO_LOG_PATH, follow=False, poll_interval=0.25, max_wait=None):
    """Yield parsed Falco JSON events from a JSON-lines file.

    When ``follow=True``, the generator tails the log and yields new records as
    they are appended in real time. This keeps the runtime monitor connected to a
    live Falco/JSONL stream instead of replaying a single static file.
    """
    if not os.path.exists(log_path):
        if follow:
            return
        return []

    def _parse_line(raw_line):
        line = raw_line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    if not follow:
        events = []
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                event = _parse_line(line)
                if event is not None:
                    events.append(event)
        return events

    with open(log_path, "r", encoding="utf-8") as handle:
        handle.seek(0, os.SEEK_END)
        started_at = time.monotonic()
        while True:
            line = handle.readline()
            if line:
                event = _parse_line(line)
                if event is not None:
                    yield event
                continue

            if max_wait is not None and (time.monotonic() - started_at) >= max_wait:
                break
            time.sleep(poll_interval)

    return


def _container_name(event):
    return (
        event.get("output_fields", {}).get("container.name")
        or event.get("container", {}).get("name")
        or "unknown"
    )


def build_feature_matrix(events):
    """
    Build a simple per-container syscall/rule-frequency feature vector.
    Each row = one container; each column = count of a given rule firing.
    """
    per_container_counts = defaultdict(Counter)
    for e in events:
        cname = _container_name(e)
        rule = e.get("rule", "unknown_rule")
        per_container_counts[cname][rule] += 1

    all_rules = sorted({r for counts in per_container_counts.values() for r in counts})
    containers = sorted(per_container_counts.keys())

    matrix = np.array([
        [per_container_counts[c][r] for r in all_rules]
        for c in containers
    ]) if containers else np.empty((0, 0))

    return containers, all_rules, matrix


def detect_anomalies(events, contamination=0.1):
    """
    Returns {container_name: {"is_anomaly": bool, "score": float, "top_rules": [...]}}.
    Falls back to rule-based flagging only if there isn't enough data to fit a model.
    """
    containers, all_rules, matrix = build_feature_matrix(events)
    results = {}

    if len(containers) >= 3 and matrix.shape[1] > 0:
        model = IsolationForest(contamination=contamination, random_state=42)
        model.fit(matrix)
        preds = model.predict(matrix)          # -1 = anomaly, 1 = normal
        scores = model.decision_function(matrix)  # lower = more anomalous
        for i, cname in enumerate(containers):
            results[cname] = {
                "is_anomaly": bool(preds[i] == -1),
                "score": float(scores[i]),
            }
    else:
        # Not enough containers to build a baseline yet — default to "normal"
        for cname in containers:
            results[cname] = {"is_anomaly": False, "score": 0.0}

    # Always escalate known high-priority rules regardless of the ML verdict
    for e in events:
        cname = _container_name(e)
        if e.get("rule") in HIGH_PRIORITY_RULES:
            results.setdefault(cname, {"is_anomaly": False, "score": 0.0})
            results[cname]["is_anomaly"] = True

    return results


if __name__ == "__main__":
    evs = read_events()
    print(f"Loaded {len(evs)} Falco events")
    anomalies = detect_anomalies(evs)
    for container, verdict in anomalies.items():
        flag = "ANOMALY" if verdict["is_anomaly"] else "normal"
        print(f"[{flag}] {container} (score={verdict['score']:.3f})")
