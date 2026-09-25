import csv
import json
import subprocess
from datetime import datetime
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import streamlit as st
from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from streamlit.components.v1 import html

matplotlib.use("Agg")

REPORT_PATH = Path("reports/risk_report.json")


@st.cache_data
def load_report(path: str = "reports/risk_report.json"):
    report_file = Path(path)
    if not report_file.exists():
        return {
            "mode": "demo",
            "ranked_findings": [],
            "attack_paths": [],
            "alerts_sent": 0,
            "_missing": True,
        }

    with report_file.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@st.cache_data
def run_scan():
    result = subprocess.run(
        ["python", "main.py", "--mode", "demo"],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(Path(__file__).resolve().parent),
    )
    return result


def detect_ai_threats(report):
    findings = report.get("ranked_findings", [])
    insights = []

    for item in findings:
        risk_score = float(item.get("risk_score", 0.0))
        exposure = float(item.get("exposure_score", 0.0))
        anomaly = float(item.get("anomaly_score", 0.0))
        violations = item.get("opa_violations", [])
        text = " ".join(violations).lower()

        if "root" in text or "privileged" in text:
            threat = "Privilege Escalation"
            rationale = "Container runs with elevated privileges and policy violations indicate direct abuse potential."
        elif exposure >= 0.6 and anomaly >= 0.8:
            threat = "Lateral Movement"
            rationale = "Exposure and behavioral anomaly suggest the workload is acting as an attacker foothold."
        elif len(violations) >= 2:
            threat = "Misconfiguration Exploit"
            rationale = "Multiple configuration regressions increase the likelihood of a successful exploit chain."
        else:
            threat = "Suspicious Activity"
            rationale = "The workload shows abnormal behavior but no major direct privilege gap."

        confidence = min(0.99, 0.55 + risk_score * 0.35 + anomaly * 0.2)
        insights.append(
            {
                "container": item.get("container_id", "unknown"),
                "title": threat,
                "severity": item.get("severity", "LOW"),
                "confidence": round(confidence, 2),
                "rationale": rationale,
                "risk_score": risk_score,
            }
        )

    return sorted(insights, key=lambda x: x["risk_score"], reverse=True)


def export_report_csv(report_path: str = "reports/risk_report.json", output_path: str = "reports/risk_report.csv"):
    report_file = Path(report_path)
    if not report_file.exists():
        raise FileNotFoundError(f"Report not found: {report_file}")

    with report_file.open("r", encoding="utf-8") as fh:
        report = json.load(fh)

    findings = report.get("ranked_findings", [])
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "container_id",
            "pod",
            "namespace",
            "image",
            "severity",
            "risk_score",
            "anomaly_score",
            "exposure_score",
            "privilege_score",
            "opa_violations",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(
                {
                    "container_id": finding.get("container_id", ""),
                    "pod": finding.get("pod", ""),
                    "namespace": finding.get("namespace", ""),
                    "image": finding.get("image", ""),
                    "severity": finding.get("severity", ""),
                    "risk_score": finding.get("risk_score", 0.0),
                    "anomaly_score": finding.get("anomaly_score", 0.0),
                    "exposure_score": finding.get("exposure_score", 0.0),
                    "privilege_score": finding.get("privilege_score", 0.0),
                    "opa_violations": "; ".join(finding.get("opa_violations", [])),
                }
            )

    return str(output_file)


def export_report_excel(report_path: str = "reports/risk_report.json", output_path: str = "reports/risk_report.xlsx"):
    report_file = Path(report_path)
    if not report_file.exists():
        raise FileNotFoundError(f"Report not found: {report_file}")

    with report_file.open("r", encoding="utf-8") as fh:
        report = json.load(fh)

    wb = Workbook()
    ws = wb.active
    ws.title = "CSPM Findings"
    ws.append([
        "container_id",
        "pod",
        "namespace",
        "image",
        "severity",
        "risk_score",
        "anomaly_score",
        "exposure_score",
        "privilege_score",
        "opa_violations",
    ])

    for item in report.get("ranked_findings", []):
        ws.append([
            item.get("container_id", ""),
            item.get("pod", ""),
            item.get("namespace", ""),
            item.get("image", ""),
            item.get("severity", ""),
            item.get("risk_score", 0.0),
            item.get("anomaly_score", 0.0),
            item.get("exposure_score", 0.0),
            item.get("privilege_score", 0.0),
            "; ".join(item.get("opa_violations", [])),
        ])

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_file)
    return str(output_file)


def export_report_pdf(report_path: str = "reports/risk_report.json", output_path: str = "reports/risk_report.pdf"):
    report_file = Path(report_path)
    if not report_file.exists():
        raise FileNotFoundError(f"Report not found: {report_file}")

    with report_file.open("r", encoding="utf-8") as fh:
        report = json.load(fh)

    findings = report.get("ranked_findings", [])
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=18, spaceAfter=12)
    body_style = styles["BodyText"]

    doc = SimpleDocTemplate(str(output_file), pagesize=letter)
    content = []
    content.append(Paragraph("CSPM Risk Report", title_style))
    content.append(Paragraph(f"Mode: {report.get('mode', 'demo')}", body_style))
    content.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    content.append(Spacer(1, 12))

    table_data = [["Container", "Severity", "Risk", "Image"]]
    for item in findings:
        table_data.append([
            item.get("container_id", ""),
            item.get("severity", "LOW"),
            str(item.get("risk_score", 0.0)),
            item.get("image", ""),
        ])

    table = Table(table_data, colWidths=[120, 80, 60, 220])
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ])
    )
    content.append(table)
    doc.build(content)
    return str(output_file)


def risk_meter(score: float):
    value = max(0.0, min(1.0, float(score)))
    percent = int(value * 100)
    if value < 0.35:
        color = "#2ecc71"
    elif value < 0.7:
        color = "#f39c12"
    else:
        color = "#e74c3c"

    gauge_html = f"""
    <div style="width:100%; max-width:260px; margin:0 auto; font-family:Arial,sans-serif;">
      <div style="background:#1f2937; border-radius:16px; padding:12px 14px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
          <span style="color:#e5e7eb; font-size:14px; font-weight:bold;">Risk score</span>
          <span style="color:{color}; font-size:20px; font-weight:bold;">{percent}%</span>
        </div>
        <div style="height:18px; background:#111827; border-radius:999px; overflow:hidden; border:1px solid #374151;">
          <div style="width:{percent}%; height:100%; background:linear-gradient(90deg, {color}, #fbbf24); border-radius:999px;"></div>
        </div>
      </div>
    </div>
    """
    html(gauge_html, height=120)


def plot_risk_distribution(findings):
    labels = [f.get("container_id", "unknown") for f in findings]
    values = [float(f.get("risk_score", 0.0)) for f in findings]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(labels, values, color=["#ef4444" if v >= 0.5 else "#f59e0b" if v >= 0.25 else "#10b981" for v in values])
    ax.set_ylabel("Risk score")
    ax.set_title("Container risk scores")
    ax.set_ylim(0, 1.0)
    fig.tight_layout()
    return fig


def plot_attack_timeline(report):
    findings = sorted(report.get("ranked_findings", []), key=lambda f: float(f.get("risk_score", 0.0)), reverse=True)
    steps = ["Observe", "Expose", "Exploit", "Contain"]
    if findings:
        values = [
            min(1.0, float(findings[0].get("risk_score", 0.0)) * 0.8),
            min(1.0, float(findings[0].get("risk_score", 0.0)) * 1.0),
            min(1.0, float(findings[1].get("risk_score", 0.0)) if len(findings) > 1 else 0.6),
            0.4,
        ]
    else:
        values = [0, 0, 0, 0]

    fig, ax = plt.subplots(figsize=(8, 3.4))
    ax.plot(steps, values, marker="o", linewidth=2.5, color="#8b5cf6")
    ax.fill_between(range(len(steps)), values, alpha=0.2, color="#8b5cf6")
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Threat level")
    ax.set_title("Attack timeline")
    ax.grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()
    return fig


st.set_page_config(page_title="CSPM Dashboard", layout="wide")
st.title("🛡️ Container Security Posture Management Dashboard")

with st.sidebar:
    st.header("Controls")
    st.caption("Run the scanner and reload the most recent security posture report.")
    if st.button("🚀 Run Full Security Scan"):
        with st.spinner("Running CSPM analysis..."):
            scan_result = run_scan()
            if scan_result.returncode == 0:
                st.success("Scan completed successfully.")
            else:
                st.error("Scan failed. Check the terminal output for details.")
                st.code(scan_result.stdout + scan_result.stderr)

    st.markdown("---")
    st.subheader("Exports")
    if st.button("Download CSV Report"):
        try:
            output_csv = export_report_csv()
            st.success(f"CSV export created: {output_csv}")
        except FileNotFoundError:
            st.warning("No report exists yet. Run a scan first.")

    if st.button("Download Excel Report"):
        try:
            output_xlsx = export_report_excel()
            st.success(f"Excel export created: {output_xlsx}")
        except FileNotFoundError:
            st.warning("No report exists yet. Run a scan first.")

    if st.button("Download PDF Report"):
        try:
            output_pdf = export_report_pdf()
            st.success(f"PDF export created: {output_pdf}")
        except FileNotFoundError:
            st.warning("No report exists yet. Run a scan first.")

    st.markdown("---")
    st.subheader("Filters")
    severity_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    namespace_filter = st.selectbox("Namespace", ["All", "production", "batch"])

report = load_report()
missing_report = report.get("_missing", False)

if missing_report:
    st.warning("No report was found. Run the security scan to generate one.")
    if st.button("Generate demo report"):
        with st.spinner("Generating report..."):
            scan_result = run_scan()
            if scan_result.returncode == 0:
                st.rerun()
            else:
                st.error(scan_result.stdout + scan_result.stderr)
    st.stop()

findings = report.get("ranked_findings", [])

if severity_filter != "All":
    findings = [f for f in findings if f.get("severity") == severity_filter]
if namespace_filter != "All":
    findings = [f for f in findings if f.get("namespace") == namespace_filter]

summary_cards = {
    "Total Containers": len(report.get("ranked_findings", [])),
    "Highest Risk": max((f.get("risk_score", 0.0) for f in report.get("ranked_findings", [])), default=0.0),
    "Critical/High": sum(1 for f in report.get("ranked_findings", []) if f.get("severity") in {"CRITICAL", "HIGH"}),
    "Alerts Sent": report.get("alerts_sent", 0),
}

ai_insights = detect_ai_threats(report)

st.subheader("AI Threat Intelligence")
if ai_insights:
    for item in ai_insights[:3]:
        st.markdown(
            f"**{item['title']}** on {item['container']} — confidence {item['confidence']:.2f} | severity {item['severity']}"
        )
        st.caption(item["rationale"])
        st.progress(min(1.0, item["confidence"]))
else:
    st.info("No AI threat insight available.")

st.markdown("---")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total containers", summary_cards["Total Containers"])
col2.metric("Highest risk", f"{summary_cards['Highest Risk']:.2f}")
col3.metric("Critical/High", summary_cards["Critical/High"])
col4.metric("Alerts sent", summary_cards["Alerts Sent"])

overview_tab, threats_tab, findings_tab, reports_tab = st.tabs(["Overview", "Threat Intel", "Findings", "Reports"])

with overview_tab:
    st.subheader("Security Overview")
    col_left, col_right = st.columns([1, 2])
    with col_left:
        top_score = max((float(f.get("risk_score", 0.0)) for f in report.get("ranked_findings", [])), default=0.0)
        risk_meter(top_score)
    with col_right:
        st.pyplot(plot_risk_distribution(report.get("ranked_findings", [])))

    st.markdown("---")
    st.subheader("Attack timeline")
    st.pyplot(plot_attack_timeline(report))

with threats_tab:
    if ai_insights:
        for item in ai_insights:
            with st.container():
                st.markdown(f"### {item['container']} — {item['title']}")
                st.write(f"Severity: {item['severity']} | Confidence: {item['confidence']:.2f}")
                st.write(item["rationale"])
                st.progress(item["confidence"])
                st.markdown("---")
    else:
        st.info("No AI threat intelligence generated.")

with findings_tab:
    if findings:
        table_rows = []
        for finding in findings:
            table_rows.append(
                {
                    "Container": finding.get("container_id"),
                    "Pod": finding.get("pod"),
                    "Namespace": finding.get("namespace"),
                    "Image": finding.get("image"),
                    "Severity": finding.get("severity"),
                    "Risk": round(float(finding.get("risk_score", 0.0)), 3),
                    "Anomaly": round(float(finding.get("anomaly_score", 0.0)), 3),
                    "Violations": len(finding.get("opa_violations", [])),
                }
            )
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

        selected = st.selectbox("Inspect finding", [row["Container"] for row in table_rows], index=0)
        selected_finding = next((f for f in findings if f.get("container_id") == selected), findings[0])

        with st.expander("Details for selected finding", expanded=True):
            st.write(f"**Container:** {selected_finding.get('container_id')}")
            st.write(f"**Pod:** {selected_finding.get('pod')}")
            st.write(f"**Namespace:** {selected_finding.get('namespace')}")
            st.write(f"**Image:** {selected_finding.get('image')}")
            st.write(f"**Severity:** {selected_finding.get('severity')}")
            st.write(f"**Risk score:** {selected_finding.get('risk_score')}")
            st.write(f"**Anomaly score:** {selected_finding.get('anomaly_score')}")
            st.write(f"**Exposure score:** {selected_finding.get('exposure_score')}")
            st.write(f"**Privilege score:** {selected_finding.get('privilege_score')}")
            st.write("**OPA violations:**")
            for violation in selected_finding.get("opa_violations", []):
                st.markdown(f"- {violation}")
    else:
        st.info("No findings match the current filters.")

with reports_tab:
    st.subheader("Report exports")
    st.write("Generate shareable exports for compliance or stakeholder review.")
    export_cols = st.columns(3)
    with export_cols[0]:
        if st.button("Export CSV"):
            try:
                st.success(f"CSV created: {export_report_csv()}")
            except FileNotFoundError:
                st.warning("No report exists yet.")
    with export_cols[1]:
        if st.button("Export Excel"):
            try:
                st.success(f"Excel created: {export_report_excel()}")
            except FileNotFoundError:
                st.warning("No report exists yet.")
    with export_cols[2]:
        if st.button("Export PDF"):
            try:
                st.success(f"PDF created: {export_report_pdf()}")
            except FileNotFoundError:
                st.warning("No report exists yet.")

    st.markdown("---")
    st.subheader("Attack paths")
    paths = report.get("attack_paths", [])
    if paths:
        for index, path in enumerate(paths, start=1):
            st.write(f"{index}. {' -> '.join(path)}")
    else:
        st.info("No attack paths detected.")

st.caption(f"Source report: {REPORT_PATH}")