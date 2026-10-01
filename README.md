# CSPM — Container Security Posture Management Framework

A lightweight, modular, real-time-simulated Container Security Posture Management
system for Docker/Kubernetes environments. It ingests configuration state,
vulnerability scan results, and runtime telemetry; detects misconfigurations
and behavioral anomalies; correlates the signals into a **unified risk score**;
and takes automated mitigation action (simulated Kubernetes admission control +
Slack/webhook alerting).

Built for a postgraduate research context: no external database, no paid
services, fully self-contained, and designed so each "Scholar Edge" idea from
the project brief maps onto a concrete module (see *Architecture* below).

---


## Quick Start — GUI Dashboard

```bash
pip install -r requirements.txt
streamlit run gui.py
```

Open the URL shown in the terminal (usually http://localhost:8501).
Click **Run Analysis** to execute the full pipeline and view the interactive risk dashboard.

## Quick Start — CLI

```bash
python main.py
python main.py --stream   # simulate live runtime telemetry
```

## 1. Project Folder Structure

```
cspm_project/
├── main.py                        # Orchestrator + CLI dashboard
├── requirements.txt
├── README.md
│
├── engines/                       # The four architectural layers
│   ├── ingestion_engine.py        # Layer 1: data ingestion / streaming
│   ├── analysis_engine.py         # Layer 2: policy-as-code + anomaly detection
│   ├── risk_engine.py             # Layer 2b: unified risk scoring / correlation
│   └── mitigation_engine.py       # Layer 3: alerting + admission control
│
├── utils/
│   ├── logger.py                  # Centralized INFO/WARNING/CRITICAL logging
│   └── models.py                  # Shared dataclasses (Container, Vuln, Event...)
│
├── storage/
│   └── json_store.py              # JSON-file persistence (no external DB)
│
├── config/
│   └── policies.yaml              # Policy-as-code rule set (OPA/Rego-style)
│
├── data/                          # Sample input fixtures
│   ├── sample_containers.json     # Simulated docker inspect / K8s manifest state
│   ├── sample_vuln_scan.json      # Simulated Trivy/Grype scan output
│   └── sample_runtime_events.json # Simulated eBPF/Falco telemetry stream
│
├── output/                        # Generated at runtime
│   ├── alerts.json
│   ├── webhook_notifications.json
│   └── risk_report.json
│
└── logs/
    └── cspm.log                   # Rotating log file
```

---

## 2. Architecture & Data Flow

```
[ Target: Docker / K8s Cluster ]
             │
             ▼
┌──────────────────────────────────────────────┐
│ 1. INGESTION ENGINE                           │
│    - Container config loader                  │
│    - Vuln scan loader (Trivy-like)             │
│    - Runtime event streamer (eBPF/Falco-like)  │
│      via generator + background thread/queue   │
└──────────────┬─────────────────────────────────┘
               │ ContainerConfig / VulnScanResult / RuntimeEvent
               ▼
┌──────────────────────────────────────────────┐
│ 2. ANALYSIS ENGINE                            │
│    - PolicyEngine: evaluates YAML rules        │
│      (privileged, root, hostNetwork/hostPID,   │
│       missing limits, public exposure) per      │
│       deployment environment                    │
│    - AnomalyDetector: IsolationForest over      │
│      per-container behavior features, with a    │
│      transparent statistical z-score fallback   │
└──────────────┬─────────────────────────────────┘
               │ MisconfigFinding[] / AnomalyResult
               ▼
┌──────────────────────────────────────────────┐
│ 3. RISK SCORING ENGINE (correlation)          │
│    Risk = VulnSeverity(1-10) x Privilege(1-3)  │
│           x Exposure(1-3) x env_multiplier      │
│    -> normalized 0-100, classified              │
│       Low / Medium / High / Critical            │
└──────────────┬─────────────────────────────────┘
               │ RiskAssessment
               ▼
┌──────────────────────────────────────────────┐
│ 4. MITIGATION ENGINE                          │
│    - Simulated K8s admission controller:       │
│      Critical -> BLOCKED, else -> ALLOWED       │
│    - Alert generation (console + alerts.json)  │
│    - Slack/webhook-style JSON notification      │
│      for High/Critical findings                 │
└──────────────────────────────────────────────┘
               │
               ▼
      CLI Risk Dashboard (main.py)
```

### Why this design maps to the research brief

| Brief requirement | Implementation |
|---|---|
| Policy-as-code (OPA/Rego) | `config/policies.yaml` + `PolicyEngine` — declarative rules evaluated per rule, per environment |
| Dynamic policy generator (dev vs prod) | Each rule has an `environments` scope; `environment_multipliers` also scale the final risk score |
| eBPF/Falco runtime detection | `RuntimeEvent` stream + `AnomalyDetector` (IsolationForest over syscall/event features) |
| Context-aware correlation | `RiskEngine` — a single weak signal (e.g. only "publicly exposed") stays Low; vuln + privilege + exposure compounding multiplicatively escalates rapidly (see `c-payment-service-02` in the sample run, which hits 100/100) |
| Unified risk formula | `Risk = Vulnerability × Privilege × Exposure`, normalized to 0–100 in `risk_engine.py` |
| Admission controller | `MitigationEngine.admission_decision()` — Critical containers are `BLOCKED` |
| Slack/webhook alerting | `MitigationEngine.dispatch_notification()` — builds a real Slack-incoming-webhook-shaped JSON payload (no network call is made) |
| Lightweight / no DB | All persistence via `storage/json_store.py`, flat JSON files only |

---

## 3. How to Run

### Prerequisites
- Python 3.9+

### Install dependencies
```bash
cd cspm_project
pip install -r requirements.txt
```
> `numpy` and `scikit-learn` are used for the IsolationForest anomaly
> detector. If they aren't installed, the framework automatically falls
> back to a transparent statistical z-score heuristic — nothing breaks.

### Run the full pipeline
```bash
python main.py
```

### Run with simulated real-time runtime-event streaming
Prints each runtime telemetry event as it "arrives" (small delay between
events) before running analysis, to visually demonstrate the streaming
ingestion architecture:
```bash
python main.py --stream
```

### Run against your own data
```bash
python main.py --containers path/to/containers.json \
                --vulns path/to/vuln_scan.json \
                --events path/to/runtime_events.json
```

### Where to look afterward
- **Console**: CLI dashboard with color-coded risk table + summary
- **`logs/cspm.log`**: full INFO/WARNING/CRITICAL audit trail
- **`output/risk_report.json`**: full structured report per container (config, misconfigs, anomaly, risk assessment, admission decision, alert)
- **`output/alerts.json`**: every alert generated, one record per container
- **`output/webhook_notifications.json`**: Slack/webhook-style payloads for High/Critical findings

---

## 4. Sample Input Data

`data/sample_containers.json` (excerpt) — a container with a critical CVE,
privileged mode, root execution, no resource limits, and public exposure:
```json
{
  "container_id": "c-payment-service-02",
  "image": "internal/payments:2.3.0",
  "namespace": "finance",
  "privileged": true,
  "run_as_root": true,
  "host_network": false,
  "host_pid": false,
  "cpu_limit": null,
  "memory_limit": null,
  "exposed_publicly": true,
  "environment": "production"
}
```

`data/sample_vuln_scan.json` (matching entry) includes a CRITICAL CVE
(simulated xz-utils backdoor, CVE-2024-3094) and a HIGH openssh CVE.

`data/sample_runtime_events.json` includes suspicious events for the same
container: an unexpected `/bin/sh` spawn, a write to `/etc/passwd`, and an
outbound connection to a "known malicious IP" — designed to trigger the
anomaly detector.

Five total sample containers are provided, spanning Low through Critical
risk, across `production`, `staging`(none in this set)/`development`
environments, to demonstrate the full classification range.

---

## 5. Sample Output

### CLI Dashboard
```
=======================================================================
===================== CSPM UNIFIED RISK DASHBOARD =====================
=======================================================================
CONTAINER ID               RISK CLASS       VULN  PRIV   EXP ADMISSION
-----------------------------------------------------------------------
c-payment-service-02     100.00 Critical      10     3     3 BLOCKED
c-web-frontend-01         21.33 Low            4     2     2 ALLOWED
c-logging-agent-03        16.00 Low            4     3     1 ALLOWED
c-redis-cache-05           9.33 Low            7     1     1 ALLOWED
c-dev-sandbox-04           0.89 Low            1     1     1 ALLOWED
=======================================================================
Summary -> Critical: 1 | Low: 4
=======================================================================
```

### `output/alerts.json` (excerpt)
```json
{
  "container_id": "c-payment-service-02",
  "classification": "Critical",
  "risk_score": 100.0,
  "summary": "Container 'c-payment-service-02' classified Critical with unified risk score 100.0/100 (vuln=10 x priv=3 x exposure=3).",
  "factors": [
    "vulnerability:max_severity=10",
    "POL-001:CRITICAL",
    "POL-002:HIGH",
    "POL-005:MEDIUM",
    "POL-006:MEDIUM",
    "POL-007:MEDIUM",
    "publicly_exposed",
    "runtime_anomaly(score=0.81)",
    "environment=production(x1.2)"
  ],
  "action_taken": "BLOCKED_BY_ADMISSION_CONTROLLER",
  "timestamp": "2026-09-15T04:50:08Z"
}
```

### `output/webhook_notifications.json` (Slack-style payload)
```json
{
  "text": ":rotating_light: *Critical risk detected* in `c-payment-service-02`\nScore: *100.0/100*\nAction: *BLOCKED_BY_ADMISSION_CONTROLLER*\nFactors: vulnerability:max_severity=10, POL-001:CRITICAL, ...",
  "container_id": "c-payment-service-02",
  "classification": "Critical",
  "risk_score": 100.0,
  "timestamp": "2026-09-15T04:50:08Z"
}
```

### Log excerpt (`logs/cspm.log`)
```
2026-09-15 04:50:04 | WARNING  | engines.analysis    | [c-payment-service-02] Policy violation POL-001: Container is running in privileged mode, granting full host access.
2026-09-15 04:50:04 | WARNING  | engines.analysis    | [c-payment-service-02] Runtime anomaly detected (score=0.81) via IsolationForest.
2026-09-15 04:50:04 | INFO     | engines.risk        | [c-payment-service-02] Risk=100.0/100 (Critical) [vuln=10 x priv=3 x exp=3, env_x1.2]
2026-09-15 04:50:04 | CRITICAL | engines.mitigation  | [ADMISSION CONTROLLER] c-payment-service-02 DENIED admission (risk=100.0/100, classification=Critical).
```

---

## 6. Extending the Project

- **Real Trivy/Falco integration**: replace `IngestionEngine`'s JSON loaders
  with subprocess calls to the real `trivy` CLI / a live Falco gRPC/HTTP
  output socket — the rest of the pipeline (`ContainerConfig`,
  `VulnScanResult`, `RuntimeEvent` dataclasses) is already shaped to match.
- **Real Kubernetes admission control**: wrap `MitigationEngine.admission_decision()`
  in a `ValidatingAdmissionWebhook` HTTP server (e.g. via `Flask`/`FastAPI`)
  returning an `AdmissionReview` response.
- **Real Slack delivery**: `dispatch_notification()` already builds a
  correctly-shaped Slack incoming-webhook payload — swap the `JSONStore.append`
  call for a `requests.post(SLACK_WEBHOOK_URL, json=payload)`.
- **Graph-based correlation** (thesis "Scholar Edge"): the `contributing_factors`
  list on each `RiskAssessment` is already structured to be loaded into a
  graph library (e.g. `networkx`) to build the attack-path correlation graph
  described in the research brief.
