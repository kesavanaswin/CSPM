# CSPM Framework — Context-Aware Container Security Posture Management

A lightweight, real-time framework that unifies vulnerability scanning,
misconfiguration auditing, and ML-based runtime anomaly detection into a
single context-aware risk score, instead of three disconnected dashboards.

## Architecture

```
[ Target: Docker / K8s Cluster ]
        │
        ▼
┌───────────────────────────────┐
│ 1. INGESTION                  │
│  ingestion/trivy_scanner.py   │  → CVE data
│  ingestion/falco_listener.py │  → runtime syscall telemetry
│  ingestion/k8s_state_reader.py│  → container specs / misconfig facts
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 2. ANALYSIS                   │
│  analysis/opa_client.py       │  → Rego policy violations
│  ml/anomaly_detector.py       │  → Isolation Forest anomaly score
│  analysis/correlation_graph.py│  → unified per-container profile + attack paths
│  analysis/risk_engine.py      │  → weighted+multiplicative risk formula
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 3. MITIGATION                  │
│  mitigation/alerting.py        │  → Slack/webhook/console alerts
│  mitigation/admission_controller.py │ → K8s ValidatingWebhook, blocks risky deploys
└───────────────────────────────┘
```

## Quick start

```bash
pip install -r requirements.txt
python main.py --mode demo
```

This runs the full pipeline against the sample data in `sample_data/` and
writes a ranked risk report to `reports/risk_report.json`.

To point it at a real cluster, set `mode: live` in `config.yaml` and:
- install the `trivy` binary and ensure it's on PATH
- run an OPA server (`opa run --server`) with `policies/*.rego` loaded
- configure Falco to write JSON events to the path in `config.yaml`
- implement `K8sStateReader._get_live()` using the `kubernetes` python client

## The risk formula (core research contribution)

```
Risk = w1*V + w2*P + w3*E + w4*A + w5*(V * P * E)
```
- V = vulnerability severity (worst CVSS score / 10)
- P = privilege level (root/privileged = 1.0, added capabilities = 0.5, else 0.1)
- E = exposure (public LB = 1.0, cluster-internal = 0.6, internal-only = 0.1)
- A = ML-derived runtime anomaly score (0–1)
- The `V*P*E` term models the "exploit chain" effect: a critical CVE that's
  also root and internet-facing should spike hard, not just add linearly.
- Weights (`w1..w5`) are configurable in `config.yaml` and should be tuned
  empirically against a labeled test set — this tuning process is itself
  a valid methodology chapter for a thesis.

This is deliberately **not** a pure multiplicative formula
(`Risk = V × E × P`) like the one in the original project brief, because
pure multiplication collapses the score toward zero whenever any single
factor is low — even if the other two indicate serious risk. The
weighted-additive-plus-multiplicative-term hybrid here avoids that failure
mode while still rewarding compounding risk. Worth stating this explicitly
in your thesis as the justification for why your formula improves on the
naive baseline.

## Mapping to the original project phases

| Phase | Requirement | Implementation |
|---|---|---|
| 1 | Misconfiguration auditing (OPA/Rego) | `policies/*.rego` + `analysis/opa_client.py` |
| 2 | Vulnerability scanning (Trivy, delta-scan) | `ingestion/trivy_scanner.py` (digest-cache delta scan) |
| 3 | Runtime anomaly detection (eBPF/Falco + ML) | `ingestion/falco_listener.py` + `ml/anomaly_detector.py` |
| 4 | Correlation & risk scoring | `analysis/correlation_graph.py` + `analysis/risk_engine.py` |
| — | Mitigation | `mitigation/alerting.py`, `mitigation/admission_controller.py` |

## Honest limitations (worth stating in your thesis, not hiding)

1. **Small-sample ML instability**: Isolation Forest with only 3 time-window
   observations per container (as in the demo data) tends to score the
   most recent point as maximally anomalous simply due to min-max
   normalization over so few points. In a real deployment you'd accumulate
   a rolling window (e.g. last 500 observations) before trusting the score —
   this is a good empirical section to include ("minimum baseline window
   size needed for stable anomaly scores").
2. **Demo mode's exposure/digest fields are simulated**, not pulled from a
   live registry or Service/Ingress lookup — the `_get_live()` and image
   digest methods are stubbed with clear `NotImplementedError`/comments
   marking exactly what real integration requires.
3. **The admission controller's "exposure" field is hardcoded** to
   `cluster_internal` for not-yet-scheduled pods, since a Service/Ingress
   mapping doesn't exist until after admission. A full implementation would
   need a secondary reconciliation pass once the Service is created.
4. **CPU overhead claims** ("<2%") in the original brief need real
   benchmarking — none is included yet. Suggested next step: run
   `main.py` under `psutil`/`cProfile` against a stress test with hundreds
   of containers and report real numbers, since this is one of your
   stated deliverables ("Empirical benchmarking").

## Suggested next increments

- Add a `benchmarks/` script measuring CPU/memory overhead vs. container count.
- Add a small web dashboard (Flask + Chart.js) reading `reports/risk_report.json`.
- Replace the exposure hardcode in `admission_controller.py` with a real
  Service/Ingress lookup via the K8s API.
- Add unit tests for `risk_engine.py` (edge cases: V=0, P=0, E=0, all=1).
