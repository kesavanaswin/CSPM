"""
Kubernetes Admission Controller (ValidatingWebhook)
----------------------------------------------------
A minimal Flask app implementing the K8s ValidatingAdmissionWebhook
contract. Real deployment requires: a TLS cert, a Service in-cluster,
and a ValidatingWebhookConfiguration pointing at this service.

For each incoming AdmissionReview request, it extracts the container
spec(s), runs them through the same OPA + risk-scoring pipeline as the
rest of the framework, and denies the request if any container's risk
score is at/above the configured block_threshold.

Run with: python mitigation/admission_controller.py
(then test with: curl -X POST localhost:5000/validate -d @sample_admission_review.json)
"""

import sys
import os
import yaml
from flask import Flask, request, jsonify

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.opa_client import OPAClient
from analysis.risk_engine import RiskEngine
from analysis.correlation_graph import CorrelationEngine
from ml.anomaly_detector import AnomalyDetector

app = Flask(__name__)

with open(os.path.join(os.path.dirname(__file__), "..", "config.yaml")) as f:
    CONFIG = yaml.safe_load(f)

opa_client = OPAClient(CONFIG)
risk_engine = RiskEngine(CONFIG)
BLOCK_THRESHOLD = CONFIG["mitigation"]["admission_controller"]["block_threshold"]


def _extract_container_spec(admission_review):
    """Pulls the first container spec out of a K8s AdmissionReview request object."""
    try:
        pod_spec = admission_review["request"]["object"]["spec"]
        containers = pod_spec.get("containers", [])
        if not containers:
            return None
        c = containers[0]
        security_ctx = c.get("securityContext", {}) or {}
        return {
            "container_id": admission_review["request"]["uid"],
            "image": c.get("image", "unknown"),
            "runAsRoot": security_ctx.get("runAsUser", 1) == 0,
            "privileged": security_ctx.get("privileged", False),
            "hostNetwork": pod_spec.get("hostNetwork", False),
            "hostPID": pod_spec.get("hostPID", False),
            "resource_limits_set": bool(c.get("resources", {}).get("limits")),
            "exposure": "cluster_internal",  # would be resolved via Service lookup in a full impl
        }
    except (KeyError, IndexError):
        return None


@app.route("/validate", methods=["POST"])
def validate():
    review = request.get_json()
    container = _extract_container_spec(review)
    uid = review.get("request", {}).get("uid", "unknown")

    if container is None:
        return jsonify({"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
                         "response": {"uid": uid, "allowed": True}})

    violations = opa_client.evaluate(container)
    ce = CorrelationEngine()
    profile = ce.build_container_profile(
        container,
        vuln_result={"vulnerabilities": []},  # live vuln data would be looked up by image digest
        opa_violations=violations,
        anomaly_score=0.0,  # no runtime history exists yet for a not-yet-running pod
    )
    scored = risk_engine.score(profile)
    allowed = scored < BLOCK_THRESHOLD

    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
            "status": {
                "message": (
                    f"CSPM risk score {scored} >= block threshold {BLOCK_THRESHOLD}. "
                    f"Violations: {violations}"
                ) if not allowed else "OK"
            }
        }
    }
    return jsonify(response)


if __name__ == "__main__":
    app.run(port=5000)
