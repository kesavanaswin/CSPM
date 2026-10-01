#!/usr/bin/env python3
"""
main.py
--------
Container Security Posture Management (CSPM) Framework
Entry point that wires together all four engines:

    Ingestion  -> Analysis (Policy + Anomaly) -> Risk Scoring -> Mitigation

and renders a CLI-based security dashboard summarizing the results.

Usage:
    python main.py
    python main.py --stream            # simulate real-time runtime event streaming
    python main.py --containers PATH --vulns PATH --events PATH
"""

import argparse
import os
import sys
import time

from engines.ingestion_engine import IngestionEngine
from engines.analysis_engine import PolicyEngine, AnomalyDetector
from engines.risk_engine import RiskEngine
from engines.mitigation_engine import MitigationEngine
from storage.json_store import JSONStore
from utils.logger import get_logger

logger = get_logger("main")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONTAINERS = os.path.join(BASE_DIR, "data", "sample_containers.json")
DEFAULT_VULNS = os.path.join(BASE_DIR, "data", "sample_vuln_scan.json")
DEFAULT_EVENTS = os.path.join(BASE_DIR, "data", "sample_runtime_events.json")
POLICY_PATH = os.path.join(BASE_DIR, "config", "policies.yaml")
ALERTS_OUTPUT = os.path.join(BASE_DIR, "output", "alerts.json")
WEBHOOK_OUTPUT = os.path.join(BASE_DIR, "output", "webhook_notifications.json")
RISK_REPORT_OUTPUT = os.path.join(BASE_DIR, "output", "risk_report.json")

_CLASSIFICATION_COLOR = {
    "Critical": "\033[91m",   # red
    "High": "\033[93m",       # yellow
    "Medium": "\033[94m",     # blue
    "Low": "\033[92m",        # green
}
_RESET = "\033[0m"


def _color(text: str, classification: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_CLASSIFICATION_COLOR.get(classification, '')}{text}{_RESET}"


def _reset_outputs():
    """Start each run with clean output artifacts."""
    for path in (ALERTS_OUTPUT, WEBHOOK_OUTPUT, RISK_REPORT_OUTPUT):
        JSONStore.save(path, [])


def print_dashboard(rows):
    """Render a simple CLI table summarizing risk assessments."""
    header = f"{'CONTAINER ID':<24} {'RISK':>6} {'CLASS':<10} {'VULN':>5} {'PRIV':>5} {'EXP':>5} {'ADMISSION':<10}"
    print("\n" + "=" * len(header))
    print(" CSPM UNIFIED RISK DASHBOARD ".center(len(header), "="))
    print("=" * len(header))
    print(header)
    print("-" * len(header))
    for row in rows:
        line = (
            f"{row['container_id']:<24} "
            f"{row['risk']:>6.2f} "
            f"{row['classification']:<10} "
            f"{row['vuln']:>5} "
            f"{row['priv']:>5} "
            f"{row['exp']:>5} "
            f"{row['admission']:<10}"
        )
        print(_color(line, row["classification"]))
    print("=" * len(header))

    summary = {}
    for row in rows:
        summary[row["classification"]] = summary.get(row["classification"], 0) + 1
    summary_line = " | ".join(f"{k}: {v}" for k, v in summary.items())
    print(f"Summary -> {summary_line}")
    print("=" * len(header) + "\n")


def run(containers_path, vulns_path, events_path, stream_mode: bool):
    logger.info("=== CSPM Framework starting ===")
    _reset_outputs()

    # ---------------- Layer 1: Ingestion ----------------
    ingestion = IngestionEngine(containers_path, vulns_path, events_path)
    containers = ingestion.load_container_configs()
    vuln_scans = ingestion.load_vuln_scans()

    if stream_mode:
        print("Streaming live runtime telemetry (tailing Falco/JSONL log)...\n")
        runtime_events = []
        try:
            for event in ingestion.stream_runtime_events(delay=0.15, follow=True, poll_interval=0.25):
                print(f"  [stream] {event.timestamp} {event.container_id:<24} "
                      f"{event.event_type:<16} suspicious={event.suspicious}")
                runtime_events.append(event)
        except KeyboardInterrupt:
            print("\nStopping live stream.")
        print()
    else:
        runtime_events = list(ingestion.stream_runtime_events(delay=0.0, follow=False))

    # ---------------- Layer 2: Analysis ----------------
    policy_engine = PolicyEngine(POLICY_PATH)
    anomaly_detector = AnomalyDetector(contamination=0.3)
    anomaly_results = anomaly_detector.analyze(runtime_events)

    # ---------------- Layer 2b + 3: Risk Scoring + Mitigation ----------------
    risk_engine = RiskEngine(environment_multipliers=policy_engine.environment_multipliers)
    mitigation_engine = MitigationEngine(ALERTS_OUTPUT, WEBHOOK_OUTPUT)

    dashboard_rows = []
    full_report = []

    for container in containers:
        misconfigs = policy_engine.evaluate(container)
        vuln_result = vuln_scans.get(container.container_id)
        anomaly = anomaly_results.get(container.container_id)

        assessment = risk_engine.assess(
            container=container,
            vuln_result=vuln_result,
            misconfigs=misconfigs,
            anomaly=anomaly,
        )
        alert = mitigation_engine.process(assessment)
        decision = mitigation_engine.admission_log()[-1]["decision"]

        dashboard_rows.append(
            {
                "container_id": container.container_id,
                "risk": assessment.normalized_score,
                "classification": assessment.classification,
                "vuln": assessment.vulnerability_score,
                "priv": assessment.privilege_score,
                "exp": assessment.exposure_score,
                "admission": decision,
            }
        )

        full_report.append(
            {
                "container": container.to_dict(),
                "misconfigurations": [m.__dict__ for m in misconfigs],
                "anomaly": anomaly.__dict__ if anomaly else None,
                "risk_assessment": assessment.to_dict(),
                "admission_decision": decision,
                "alert": alert.to_dict(),
            }
        )

    dashboard_rows.sort(key=lambda r: r["risk"], reverse=True)
    print_dashboard(dashboard_rows)

    JSONStore.save(RISK_REPORT_OUTPUT, full_report)
    logger.info(f"Full risk report written to {RISK_REPORT_OUTPUT}")
    logger.info(f"Alerts written to {ALERTS_OUTPUT}")
    logger.info(f"Webhook notifications written to {WEBHOOK_OUTPUT}")
    logger.info("=== CSPM Framework run complete ===")


def parse_args():
    parser = argparse.ArgumentParser(description="Container Security Posture Management (CSPM) Framework")
    parser.add_argument("--containers", default=DEFAULT_CONTAINERS, help="Path to container config JSON")
    parser.add_argument("--vulns", default=DEFAULT_VULNS, help="Path to vulnerability scan JSON")
    parser.add_argument("--events", default=DEFAULT_EVENTS, help="Path to runtime events JSON")
    parser.add_argument("--stream", action="store_true", help="Simulate real-time runtime event streaming")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start = time.time()
    try:
        run(args.containers, args.vulns, args.events, args.stream)
    except Exception as e:  # top-level safety net
        logger.critical(f"CSPM run failed with unhandled exception: {e}", exc_info=True)
        sys.exit(1)
    logger.info(f"Total execution time: {time.time() - start:.2f}s")
