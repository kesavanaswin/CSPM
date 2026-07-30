# CSPM Framework — Container Security Posture Management

A lightweight, unified, context-aware framework that correlates configuration
misconfigurations, image vulnerabilities, and runtime anomalies into a single
risk score, instead of showing them as separate, disconnected alerts.

Built in Python, matching the architecture in the project synopsis:
Ingestion → Analysis → Correlation → Mitigation.

## Project Structure

```
cspm_project/
├── app.py                          # Flask entry point + pipeline orchestration
├── config.py                       # All tunables (paths, weights, thresholds)
├── models.py                       # SQLite schema + persistence helpers
├── config_audit.py                 # Phase 1: OPA/Rego config auditing (+Python fallback)
├── vuln_scan.py                    # Phase 2: Trivy wrapper with delta-scan caching
├── runtime_monitor.py              # Phase 3: Falco event parsing + Isolation Forest
├── risk_engine.py                  # Phase 4: Correlation & unified risk scoring
├── policies/
│   └── container_security.rego     # Sample OPA policy (privileged, root, limits, hostNetwork...)
├── templates/
│   └── dashboard.html              # Unified risk dashboard UI
├── samples/
│   ├── sample_pod.yaml             # Example K8s manifest to test config_audit.py
│   └── falco_events.jsonl          # Example Falco alerts to test runtime_monitor.py
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optional external tools (the framework degrades gracefully without them):
- **OPA**: https://www.openpolicyagent.org/docs/latest/#running-opa — without it,
  `config_audit.py` uses an equivalent pure-Python rule set.
- **Trivy**: https://aquasecurity.github.io/trivy/ — without it, vulnerability
  scanning is skipped and reported as `"trivy binary not found on PATH"`.
- **Falco**: https://falco.org/docs/setup/ — configure its `file` or `http`
  output to write JSON alerts to the path in `config.FALCO_LOG_PATH`.

## Running

```bash
python app.py
```

Visit `http://localhost:5000` for the dashboard.

## Triggering a scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "manifest_path": "samples/sample_pod.yaml",
    "image": "myregistry/api-backend:1.4.2",
    "container_name": "api-backend",
    "namespace": "production",
    "k8s_service_type": "LoadBalancer"
  }'
```

This runs all four phases and stores the result in `cspm.db`:
1. **Config audit** — checks the manifest against `policies/container_security.rego`
2. **Vulnerability scan** — scans the image with Trivy (delta-scanned by image digest)
3. **Runtime check** — reads Falco events and flags anomalies via Isolation Forest
4. **Correlation** — computes `Risk = Vulnerability × Exposure × Privilege`,
   escalated further if a runtime anomaly is active

## Testing individual modules

```bash
python config_audit.py samples/sample_pod.yaml
python runtime_monitor.py
python vuln_scan.py myregistry/api-backend:1.4.2
```

## Slack Alerts

Set an environment variable before running the app to enable alerting for
CRITICAL/HIGH risk containers:

```bash
export CSPM_SLACK_WEBHOOK="https://hooks.slack.com/services/your/webhook/url"
python app.py
```

## Extending

- **Real-time Falco streaming**: replace `runtime_monitor.read_events()` with a
  Unix socket or HTTP listener instead of reading a static file.
- **Kubernetes Admission Controller**: add a `ValidatingWebhookConfiguration`
  that calls `run_pipeline()` synchronously and rejects the Pod if
  `risk["severity_label"] == "CRITICAL"`.
- **Graph-based correlation**: `risk_engine.build_exploit_chain_explanation()`
  is the starting point for a richer attack-path graph (e.g. using `networkx`).
