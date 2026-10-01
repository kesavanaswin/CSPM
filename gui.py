#!/usr/bin/env python3
"""
gui.py — Streamlit Web Dashboard for the CSPM System
----------------------------------------------------
Run with:
    streamlit run gui.py

Interactive security posture dashboard with:
  • Unified risk overview cards
  • Risk score table + charts
  • Policy violations & runtime anomalies
  • Admission controller decisions
  • Alerts and notifications
"""

import os
import sys
from datetime import datetime

import streamlit as st
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from engines.ingestion_engine import IngestionEngine
from engines.analysis_engine import PolicyEngine, AnomalyDetector
from engines.risk_engine import RiskEngine
from engines.mitigation_engine import MitigationEngine
from storage.json_store import JSONStore

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DEFAULT_CONTAINERS = os.path.join(BASE_DIR, "data", "sample_containers.json")
DEFAULT_VULNS = os.path.join(BASE_DIR, "data", "sample_vuln_scan.json")
DEFAULT_EVENTS = os.path.join(BASE_DIR, "data", "sample_runtime_events.json")
POLICY_PATH = os.path.join(BASE_DIR, "config", "policies.yaml")
ALERTS_OUTPUT = os.path.join(BASE_DIR, "output", "alerts.json")
WEBHOOK_OUTPUT = os.path.join(BASE_DIR, "output", "webhook_notifications.json")
RISK_REPORT_OUTPUT = os.path.join(BASE_DIR, "output", "risk_report.json")

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CSPM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 1.2rem; }
    div[data-testid="stMetricValue"] { font-size: 1.7rem; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner="Running CSPM analysis pipeline…")
def run_pipeline(containers_path: str, vulns_path: str, events_path: str):
    for path in (ALERTS_OUTPUT, WEBHOOK_OUTPUT, RISK_REPORT_OUTPUT):
        JSONStore.save(path, [])

    # Layer 1 — Ingestion
    ingestion = IngestionEngine(containers_path, vulns_path, events_path)
    containers = ingestion.load_container_configs()
    vuln_scans = ingestion.load_vuln_scans()          # Dict[str, VulnScanResult]
    runtime_events = list(ingestion.stream_runtime_events(delay=0.0))

    # Layer 2 — Analysis
    policy_engine = PolicyEngine(POLICY_PATH)
    anomaly_detector = AnomalyDetector(contamination=0.3)
    anomaly_results = anomaly_detector.analyze(runtime_events)  # Dict[str, AnomalyResult]

    # Layer 2b + 3 — Risk + Mitigation
    risk_engine = RiskEngine(environment_multipliers=policy_engine.environment_multipliers)
    mitigation = MitigationEngine(ALERTS_OUTPUT, WEBHOOK_OUTPUT)

    assessments = []
    misconfigs_map = {}
    admission_map = {}
    alerts = []
    full_report = []

    for container in containers:
        cid = container.container_id
        misconfigs = policy_engine.evaluate(container)
        misconfigs_map[cid] = misconfigs
        vuln_result = vuln_scans.get(cid)
        anomaly = anomaly_results.get(cid)

        assessment = risk_engine.assess(
            container=container,
            vuln_result=vuln_result,
            misconfigs=misconfigs,
            anomaly=anomaly,
        )
        assessments.append(assessment)

        alert = mitigation.process(assessment)
        decision = mitigation.admission_log()[-1]["decision"]
        admission_map[cid] = decision
        alerts.append(alert)

        full_report.append({
            "container": container.to_dict(),
            "misconfigurations": [m.__dict__ for m in misconfigs],
            "anomaly": anomaly.__dict__ if anomaly else None,
            "risk_assessment": assessment.to_dict(),
            "admission_decision": decision,
            "alert": alert.to_dict(),
        })

    JSONStore.save(RISK_REPORT_OUTPUT, full_report)

    return {
        "containers": containers,
        "assessments": assessments,
        "misconfigs": misconfigs_map,
        "anomalies": anomaly_results,
        "alerts": alerts,
        "admission": admission_map,
        "vuln_scans": vuln_scans,
    }


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ CSPM")
    st.caption("Container Security Posture Management")
    st.markdown("---")

    st.subheader("Data Sources")
    containers_path = st.text_input("Containers JSON", DEFAULT_CONTAINERS)
    vulns_path = st.text_input("Vuln Scans JSON", DEFAULT_VULNS)
    events_path = st.text_input("Runtime Events JSON", DEFAULT_EVENTS)

    run_btn = st.button("▶ Run Analysis", type="primary", use_container_width=True)
    clear_btn = st.button("Clear Cache", use_container_width=True)

    if clear_btn:
        st.cache_data.clear()
        st.rerun()

    st.markdown("---")
    st.markdown(
        "**Risk Formula**  \n"
        "`Risk = Vulnerability × Privilege × Exposure`  \n"
        "× environment multiplier"
    )
    st.markdown("---")
    st.caption(
        "Modules: Config Audit · Vuln Scan · Runtime · "
        "Correlation · Risk Scoring · Alerting"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
st.title("Container Security Posture Dashboard")
st.caption(f"Last refreshed · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if run_btn or "results" not in st.session_state:
    results = run_pipeline(containers_path, vulns_path, events_path)
    st.session_state["results"] = results
else:
    results = st.session_state["results"]

assessments = results["assessments"]
admission = results["admission"]
misconfigs = results["misconfigs"]
anomalies = results["anomalies"]
alerts = results["alerts"]
vuln_scans = results["vuln_scans"]

# ---------- Summary metrics ----------
total = len(assessments)
critical = sum(1 for a in assessments if a.classification == "Critical")
high = sum(1 for a in assessments if a.classification == "High")
blocked = sum(1 for d in admission.values() if d == "BLOCKED")
avg_risk = sum(a.normalized_score for a in assessments) / total if total else 0.0

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Containers", total)
m2.metric("Critical", critical)
m3.metric("High", high)
m4.metric("Blocked", blocked)
m5.metric("Avg Risk", f"{avg_risk:.1f}")

st.markdown("---")

# ---------- Risk table ----------
st.subheader("Unified Risk Assessment")

rows = []
for a in sorted(assessments, key=lambda x: x.normalized_score, reverse=True):
    rows.append({
        "Container": a.container_id,
        "Risk Score": round(a.normalized_score, 2),
        "Class": a.classification,
        "Vuln": a.vulnerability_score,
        "Privilege": a.privilege_score,
        "Exposure": a.exposure_score,
        "Admission": admission.get(a.container_id, "—"),
        "Top Factors": ", ".join(a.contributing_factors[:3])
                       + ("…" if len(a.contributing_factors) > 3 else ""),
    })

df = pd.DataFrame(rows)

def _style_class(val):
    return {
        "Critical": "background-color:#7f1d1d;color:white;font-weight:600",
        "High": "background-color:#9a3412;color:white;font-weight:600",
        "Medium": "background-color:#1e3a8a;color:white",
        "Low": "background-color:#14532d;color:white",
    }.get(val, "")

def _style_admission(val):
    if val == "BLOCKED":
        return "background-color:#7f1d1d;color:white;font-weight:700"
    return "background-color:#14532d;color:white"

styled = (
    df.style
    .map(_style_class, subset=["Class"])
    .map(_style_admission, subset=["Admission"])
    .format({"Risk Score": "{:.2f}"})
)

st.dataframe(styled, use_container_width=True, hide_index=True)

# ---------- Charts ----------
left, right = st.columns([1.3, 1])

with left:
    st.subheader("Risk Score by Container")
    chart_df = (
        pd.DataFrame({
            "Container": [a.container_id for a in assessments],
            "Risk": [a.normalized_score for a in assessments],
        })
        .sort_values("Risk", ascending=True)
        .set_index("Container")
    )
    st.bar_chart(chart_df, height=300)

with right:
    st.subheader("Classification Breakdown")
    class_counts = pd.Series([a.classification for a in assessments]).value_counts()
    st.bar_chart(class_counts, height=300)

st.markdown("---")

# ---------- Per-container detail ----------
st.subheader("Detailed Findings")

for a in sorted(assessments, key=lambda x: x.normalized_score, reverse=True):
    cid = a.container_id
    icon = {"Critical": "🔴", "High": "🟠", "Medium": "🔵", "Low": "🟢"}.get(a.classification, "⚪")
    expanded = a.classification in ("Critical", "High")

    with st.expander(
        f"{icon}  {cid}   ·   Risk {a.normalized_score:.1f}/100   ·   "
        f"{a.classification}   ·   {admission.get(cid, '—')}",
        expanded=expanded,
    ):
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Vulnerability", a.vulnerability_score)
        k2.metric("Privilege", a.privilege_score)
        k3.metric("Exposure", a.exposure_score)
        k4.metric("Admission", admission.get(cid, "—"))

        st.markdown("**Contributing Factors**")
        if a.contributing_factors:
            for f in a.contributing_factors:
                st.markdown(f"- `{f}`")
        else:
            st.caption("None")

        findings = misconfigs.get(cid, [])
        if findings:
            st.markdown("**Policy Violations**")
            for f in findings:
                st.warning(f"**{f.rule_id}** ({f.severity}) — {f.description}")

        anomaly = anomalies.get(cid)
        if anomaly and anomaly.is_anomalous:
            st.error(
                f"**Runtime Anomaly** (score={anomaly.anomaly_score:.2f}, "
                f"method={anomaly.method}) — {anomaly.details or 'Suspicious behavior detected'}"
            )
        elif anomaly:
            st.success(f"Runtime behavior normal (score={anomaly.anomaly_score:.2f})")

        vuln = vuln_scans.get(cid)
        if vuln and vuln.findings:
            st.markdown("**Vulnerability Findings**")
            vuln_df = pd.DataFrame([
                {
                    "CVE": f.cve_id,
                    "Package": f.package,
                    "Severity": f.severity,
                    "Fixed In": f.fixed_version or "—",
                }
                for f in vuln.findings
            ])
            st.dataframe(vuln_df, hide_index=True, use_container_width=True)

st.markdown("---")

# ---------- Alerts ----------
st.subheader("Alerts & Notifications")
high_crit = [a for a in alerts if a.classification in ("Critical", "High")]
if high_crit:
    for alert in high_crit:
        icon = "🚨" if alert.classification == "Critical" else "⚠️"
        st.markdown(
            f"{icon} **{alert.container_id}** — {alert.classification} "
            f"(score {alert.risk_score:.1f}) → **{alert.action_taken}**"
        )
        st.caption(alert.summary)
else:
    st.info("No High or Critical alerts in this run.")

st.markdown("---")
st.caption(
    "CSPM Framework  ·  Configuration Auditing  ·  Vulnerability Scanning  ·  "
    "Runtime Monitoring  ·  Correlation Engine  ·  Risk Scoring  ·  Alerting"
)

