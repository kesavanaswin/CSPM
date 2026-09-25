"""
CSPM Framework - Main Orchestrator
==================================
Wires together: Ingestion -> Analysis (OPA + ML + Correlation + Risk Scoring)
-> Mitigation (Alerting), per the 3-layer architecture in the project spec.

Usage:
    python main.py                 # runs in whatever mode config.yaml specifies
    python main.py --mode demo     # force demo mode (offline, uses sample_data/)
    python main.py --mode live     # force live mode (requires trivy/OPA/Falco/K8s)
"""

import argparse
import json
import os
import yaml

from ingestion.trivy_scanner import TrivyScanner
from ingestion.falco_listener import FalcoListener
from ingestion.k8s_state_reader import K8sStateReader

from analysis.opa_client import OPAClient
from analysis.correlation_graph import CorrelationEngine
from analysis.risk_engine import RiskEngine

from ml.anomaly_detector import AnomalyDetector

from mitigation.alerting import Alerter


def load_config(path="config.yaml", mode_override=None):
    with open(path) as f:
        config = yaml.safe_load(f)
    if mode_override:
        config["mode"] = mode_override
    return config


def run_pipeline(config):
    print(f"\n=== CSPM Framework running in '{config['mode'].upper()}' mode ===\n")

    # ---- 1. INGESTION ----
    k8s_reader = K8sStateReader(config)
    containers = k8s_reader.get_containers()
    print(f"[ingestion] Loaded {len(containers)} container(s) from K8s state.")

    trivy = TrivyScanner(config)
    vuln_results = {}
    for c in containers:
        result = trivy.scan_image(c["image"])
        vuln_results[c["container_id"]] = result
    print(f"[ingestion] Trivy scan complete for {len(vuln_results)} image(s).")

    falco = FalcoListener(config)
    events_by_container = falco.events_by_container()
    print(f"[ingestion] Falco/eBPF telemetry loaded for {len(events_by_container)} container(s).")

    # ---- 2. ANALYSIS ----
    opa = OPAClient(config)
    violations_by_container = opa.evaluate_all(containers)
    print(f"[analysis] OPA policy evaluation complete.")

    detector = AnomalyDetector(config)
    anomaly_scores = detector.score_all(events_by_container)
    print(f"[analysis] ML anomaly scoring complete: {anomaly_scores}")

    ce = CorrelationEngine()
    profiles = {}
    for c in containers:
        cid = c["container_id"]
        profile = ce.build_container_profile(
            container=c,
            vuln_result=vuln_results.get(cid, {"vulnerabilities": []}),
            opa_violations=violations_by_container.get(cid, []),
            anomaly_score=anomaly_scores.get(cid, 0.0),
        )
        profiles[cid] = profile
    ce.link_related_containers(containers)
    paths = ce.attack_paths()
    print(f"[analysis] Correlation graph built. Candidate attack paths: {paths}")

    risk_engine = RiskEngine(config)
    scored = risk_engine.score_all(profiles)
    ranked = sorted(scored.values(), key=lambda r: r["risk_score"], reverse=True)

    # ---- 3. MITIGATION ----
    alerter = Alerter(config)
    alerted = alerter.notify(ranked)

    # ---- REPORT ----
    os.makedirs("reports", exist_ok=True)
    report = {
        "mode": config["mode"],
        "ranked_findings": ranked,
        "attack_paths": paths,
        "alerts_sent": len(alerted),
    }
    with open("reports/risk_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\n=== RISK REPORT (ranked, highest first) ===")
    for r in ranked:
        print(f"  {r['severity']:8s} | {r['container_id']:6s} | {r['image']:22s} | "
              f"risk={r['risk_score']:.3f} | violations={len(r['opa_violations'])} | "
              f"anomaly={r['anomaly_score']}")
    print(f"\nFull report saved to reports/risk_report.json\n")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSPM Framework")
    parser.add_argument("--mode", choices=["demo", "live"], default=None,
                         help="Override the mode set in config.yaml")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config, mode_override=args.mode)
    run_pipeline(cfg)
