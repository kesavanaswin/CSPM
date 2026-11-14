# CSPM — Container Security Posture Management Framework

A lightweight, modular Container Security Posture Management (CSPM) framework for Docker/Kubernetes environments. It evaluates container configuration and vulnerability data, analyzes runtime telemetry, correlates findings into a unified risk score, and generates alerts with a **simulated** admission-control decision.

> **Runtime streaming status:** `python main.py --stream` watches a JSON Lines (JSONL) event file and processes events as they arrive. This is file-based near-real-time ingestion, not a direct Falco/eBPF socket integration or production Kubernetes enforcement. Risk scoring and output behavior are described below; see [Streaming mode](#streaming-mode) for details.

Built for a postgraduate research context: no external database or paid services are required. The modules are designed to map research ideas to concrete implementations.

---

## Quick Start — GUI Dashboard

```bash
pip install -r requirements.txt
streamlit run gui.py
```

Open the URL shown in the terminal (usually http://localhost:8501) and click **Run Analysis**.

## Quick Start — CLI

```bash
pip install -r requirements.txt
python main.py                 # analyze fixture data once
python main.py --stream        # follow a JSONL runtime-event file
```

---

## 1. Project Structure

```
CSPM/
├── main.py                        # Pipeline orchestrator and CLI dashboard
├── app.py                         # Flask API and web dashboard
├── gui.py                         # Streamlit dashboard
├── config.py                      # Runtime paths and scoring configuration
├── config_audit.py                # Manifest/configuration auditing
├── vuln_scan.py                   # Vulnerability scanner integration
├── runtime_monitor.py             # Falco JSONL reader and anomaly detection
├── risk_engine.py                 # Risk correlation and scoring
├── engines/                       # Modular ingestion, analysis, risk, mitigation
├── utils/                          # Shared models and logging
├── storage/                        # Lightweight local persistence helpers
├── config/policies.yaml            # Policy-as-code rules for the modular pipeline
├── data/                           # Sample input fixtures
├── samples/                        # Sample Kubernetes manifest and Falco events
├── templates/                      # Flask dashboard templates
├── output/                         # Generated reports and alerts
└── tests/                           # Automated tests
```

---

## 2. Architecture

1. **Ingestion** loads container and vulnerability snapshots, and reads runtime events from JSON/JSONL.
2. **Analysis** evaluates configuration policies and detects runtime anomalies.
3. **Risk scoring** correlates vulnerability severity, privilege, exposure, environment, and runtime signals.
4. **Mitigation** writes alerts and webhook-shaped notification records; admission control is simulated.

The `engines/` modules power `main.py`. The Flask application (`app.py`) is a separate pipeline entry point. The project includes sample data and integration points, but it does not automatically connect to or enforce policy on a live Kubernetes cluster.

---

## 3. Run the CLI

### Prerequisites

- Python 3.9+

Install dependencies:

```bash
pip install -r requirements.txt
```

`numpy` and `scikit-learn` support Isolation Forest anomaly detection. Where supported by the code, a statistical fallback is used if those optional packages are unavailable.

### Batch analysis

```bash
python main.py
```

This loads the configured container, vulnerability, and runtime-event fixture files, performs analysis, prints the dashboard, and writes reports under `output/`.

### Streaming mode

```bash
python main.py --stream
```

Streaming mode follows the runtime-event file passed through `--events`. The default path is `data/sample_runtime_events.json`; for Falco-style JSON Lines, pass a `.jsonl` file, for example:

```bash
python main.py --stream --events samples/falco_events.jsonl
```

The file must contain one JSON event per line. Append new events from the producer to the file while the command is running. Stop the process with **Ctrl+C**. The stream can be tested locally by appending a sample-shaped JSON record:

```bash
printf '%s\n' '{"container_id":"api-backend","event_type":"process_spawn","detail":"unexpected shell","timestamp":"2026-01-01T00:00:00Z","suspicious":true}' >> samples/falco_events.jsonl
```

The event schema used by the engine is `RuntimeEvent`: `container_id`, `event_type`, and `detail` are required; `timestamp`, `syscall`, and `suspicious` are optional. The modular ingestion layer reads existing JSONL records and then waits for appended lines in follow mode.

> **Important:** file-tail streaming is not equivalent to a production Falco integration. It does not collect kernel events itself. Configure Falco or another trusted producer to write compatible JSONL, or implement a socket/HTTP adapter. The live stream should be validated against your checked-out code and tests before relying on its dashboard or alerts for continuous monitoring.

### Use custom batch data

```bash
python main.py \
  --containers path/to/containers.json \
  --vulns path/to/vuln_scan.json \
  --events path/to/runtime_events.json
```

---

## 4. Run the Flask API

```bash
python app.py
```

The Flask app serves a dashboard and JSON endpoints. `POST /api/scan` accepts a manifest path, image, container name, and optional namespace/service details. Review `app.py` and configure the required tools and paths before using it with your own environment.

---

## 5. Inputs and Outputs

### Runtime events

- `data/sample_runtime_events.json` is the batch-mode fixture used by `main.py` by default.
- `samples/falco_events.jsonl` demonstrates Falco-shaped JSON-line events. The modular stream expects records that can be parsed into the project’s `RuntimeEvent` model. If the producer’s field names differ, adapt the ingestion mapping.

### Generated outputs

- `output/risk_report.json` — structured container assessments.
- `output/alerts.json` — generated alert records.
- `output/webhook_notifications.json` — webhook-shaped notification payloads.
- `logs/cspm.log` — application logs, when logging is configured to write there.

Outputs are local files and may contain environment details; protect them accordingly.

---

## 6. What Is Simulated and What Is Not

- **Runtime events:** JSON/JSONL ingestion is implemented; direct eBPF collection and native Falco socket/gRPC integration are not included.
- **Anomaly detection:** the project’s model/heuristics operate on the events supplied to it; they do not establish a production-grade learned baseline automatically.
- **Admission control:** a risk-based decision is logged by the application; it does not block a real Kubernetes pod.
- **Notifications:** the modular pipeline writes webhook-shaped payloads locally. Any actual external delivery requires explicit integration and secure configuration.
- **Scanning and configuration auditing:** tool integration depends on the selected entry point, installed dependencies/binaries, and local configuration. Validate behavior in a test environment before connecting production assets.

---

## 7. Extending the Project

- Integrate Falco through a supported JSON output, gRPC, or HTTP transport and map its event schema into `RuntimeEvent`.
- Add resilient file rotation/reconnect behavior or use a durable event transport for long-running deployments.
- Recompute and persist per-container state incrementally, deduplicate alerts, and expose an authenticated dashboard/API for continuous operation.
- Implement a real Kubernetes `ValidatingAdmissionWebhook` separately; do not treat the current simulated decision as enforcement.
- Add tests for malformed/partial JSONL lines, file rotation, interruption, duplicate alert suppression, and event-to-container mapping.

## License

See [LICENSE](LICENSE).
