"""
CSPM Framework — Flask entry point.

Routes:
  GET  /                    -> dashboard (unified, correlated risk view)
  POST /api/scan            -> run the full pipeline against a manifest + image
  GET  /api/dashboard        -> raw JSON of dashboard data
  GET  /api/containers/<id>  -> drill-down detail for one container

Run with:  python app.py
"""

import os
import time

from flask import Flask, jsonify, render_template, request

import models
import config_audit
import vuln_scan
import runtime_monitor
import risk_engine
from config import SLACK_WEBHOOK_URL

app = Flask(__name__)


def send_slack_alert(message):
    if not SLACK_WEBHOOK_URL:
        print(f"[ALERT - no webhook configured] {message}")
        return
    import requests
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=5)
    except requests.RequestException as exc:
        print(f"Failed to send Slack alert: {exc}")


def run_pipeline(manifest_path, image, container_name, namespace, k8s_service_type=None, force_scan=False):
    """
    Executes all four phases end-to-end for one container and persists results:
      1. Config audit (OPA/Rego or Python fallback)
      2. Vulnerability scan (Trivy, with delta-scan caching)
      3. Runtime anomaly check (Falco events + Isolation Forest)
      4. Correlation & unified risk score
    """
    manifest = config_audit.load_manifest(manifest_path)
    privilege, exposure = config_audit.infer_privilege_and_exposure(manifest, k8s_service_type)

    container_id = models.upsert_container(
        name=container_name, namespace=namespace, image=image,
        exposure=exposure, privilege=privilege,
    )

    # --- Phase 1: Config audit ---
    config_findings = config_audit.audit_manifest(manifest_path)
    for msg in config_findings:
        models.add_config_finding(container_id, rule="config_audit", message=msg, severity="MEDIUM")

    # --- Phase 2: Vulnerability scan ---
    scan_result = vuln_scan.scan_image(image, force=force_scan)
    vuln_findings = scan_result["findings"]
    for f in vuln_findings:
        models.add_vuln_finding(
            container_id, f["cve_id"], f["package"],
            f["installed_version"], f["fixed_version"], f["severity"],
        )

    # --- Phase 3: Runtime anomaly detection ---
    events = runtime_monitor.read_events()
    anomalies = runtime_monitor.detect_anomalies(events)
    verdict = anomalies.get(container_name, {"is_anomaly": False, "score": 0.0})
    for e in events:
        if e.get("output_fields", {}).get("container.name") == container_name:
            models.add_runtime_event(
                container_id, rule=e.get("rule", "unknown"),
                priority=e.get("priority", "Notice"), output=e.get("output", ""),
                is_anomaly=verdict["is_anomaly"],
            )

    # --- Phase 4: Correlation & risk scoring ---
    risk = risk_engine.compute_risk(
        vuln_findings, exposure, privilege, is_runtime_anomaly=verdict["is_anomaly"],
    )
    models.add_risk_score(
        container_id, risk["vulnerability_score"], risk["exposure_score"],
        risk["privilege_score"], risk["total_score"], risk["severity_label"],
    )

    explanation = risk_engine.build_exploit_chain_explanation(
        container_name, risk, config_findings, vuln_findings,
    )

    if risk["severity_label"] in ("CRITICAL", "HIGH"):
        send_slack_alert(f":rotating_light: [{risk['severity_label']}] {explanation}")

    return {
        "container_id": container_id,
        "config_findings": config_findings,
        "vulnerability_scan": scan_result,
        "runtime_verdict": verdict,
        "risk": risk,
        "explanation": explanation,
    }


@app.route("/")
def dashboard():
    data = models.get_dashboard_data()
    return render_template("dashboard.html", rows=data)


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(models.get_dashboard_data())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Expected JSON body:
    {
      "manifest_path": "samples/sample_pod.yaml",
      "image": "myregistry/api-backend:1.4.2",
      "container_name": "api-backend",
      "namespace": "production",
      "k8s_service_type": "LoadBalancer",
      "force_scan": false
    }
    """
    payload = request.get_json(force=True)
    try:
        result = run_pipeline(
            manifest_path=payload["manifest_path"],
            image=payload["image"],
            container_name=payload["container_name"],
            namespace=payload.get("namespace", "default"),
            k8s_service_type=payload.get("k8s_service_type"),
            force_scan=payload.get("force_scan", False),
        )
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


if __name__ == "__main__":
    models.init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
