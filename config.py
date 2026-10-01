"""
Central configuration for the CSPM framework.
Edit these values to match your environment.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Database ---
DB_PATH = os.path.join(BASE_DIR, "cspm.db")

# --- Config Auditing (OPA) ---
OPA_BINARY = "opa"                     # must be on PATH, or give full path e.g. /usr/local/bin/opa
POLICY_DIR = os.path.join(BASE_DIR, "policies")
DEFAULT_POLICY_FILE = os.path.join(POLICY_DIR, "container_security.rego")

# --- Vulnerability Scanning (Trivy) ---
TRIVY_BINARY = "trivy"                 # must be on PATH, or give full path
TRIVY_SEVERITY = "CRITICAL,HIGH,MEDIUM"

# --- Runtime Monitoring (Falco) ---
# Falco can be configured to write JSON alerts to a file via its "file" output,
# or stream them over a unix socket / http endpoint. This project reads from a
# JSON-lines log file for simplicity; swap in a socket/HTTP listener in production.
FALCO_LOG_PATH = os.path.join(BASE_DIR, "samples", "falco_events.jsonl")

# --- Risk Scoring weights (Risk = Vulnerability x Exposure x Privilege) ---
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "UNKNOWN": 1,
}
EXPOSURE_WEIGHTS = {
    "internet": 3,      # publicly exposed via LoadBalancer/Ingress/NodePort
    "cluster": 2,       # reachable only inside the cluster
    "internal": 1,      # ClusterIP, no ingress
}
PRIVILEGE_WEIGHTS = {
    "privileged": 3,
    "root": 2,
    "non_root": 1,
}

# Alert routing
SLACK_WEBHOOK_URL = os.environ.get("CSPM_SLACK_WEBHOOK", "")  # set as env var, keep out of code
RISK_ALERT_THRESHOLD = 50   # scores >= this trigger an alert
