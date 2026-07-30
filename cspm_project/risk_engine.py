"""
Phase 4: Correlation & Unified Risk Scoring

This is the framework's primary research contribution: instead of showing
config findings, vulnerabilities, and runtime alerts as separate disconnected
lists, they are correlated per-container into a single, context-aware score.

    Risk = Vulnerability_score x Exposure_score x Privilege_score

- Vulnerability_score: derived from the worst CVE severity found in the image
- Exposure_score:      how reachable the container is (internet > cluster > internal)
- Privilege_score:     how much host/OS privilege the container runs with

A runtime anomaly (from runtime_monitor.py) acts as a multiplier on top of
the base score, since "vulnerable AND actively behaving strangely" is far
more urgent than "vulnerable but quiet."
"""

from config import SEVERITY_WEIGHTS, EXPOSURE_WEIGHTS, PRIVILEGE_WEIGHTS, RISK_ALERT_THRESHOLD


def _worst_severity_weight(vuln_findings):
    if not vuln_findings:
        return 1  # baseline weight even with zero known CVEs
    weights = [SEVERITY_WEIGHTS.get(v["severity"].upper(), 1) for v in vuln_findings]
    return max(weights)


def compute_risk(vuln_findings, exposure, privilege, is_runtime_anomaly=False):
    """
    vuln_findings: list of dicts from vuln_scan.scan_image()["findings"]
    exposure:      "internet" | "cluster" | "internal"
    privilege:     "privileged" | "root" | "non_root"
    is_runtime_anomaly: bool, from runtime_monitor.detect_anomalies()

    Returns dict with component scores, total_score, and a severity_label.
    """
    vuln_score = _worst_severity_weight(vuln_findings)
    exposure_score = EXPOSURE_WEIGHTS.get(exposure, 1)
    privilege_score = PRIVILEGE_WEIGHTS.get(privilege, 1)

    total = vuln_score * exposure_score * privilege_score

    # Active runtime anomaly escalates the score rather than just adding a flag,
    # reflecting that an exploited vulnerability is more urgent than a dormant one.
    if is_runtime_anomaly:
        total *= 1.5

    if total >= RISK_ALERT_THRESHOLD:
        label = "CRITICAL"
    elif total >= RISK_ALERT_THRESHOLD * 0.6:
        label = "HIGH"
    elif total >= RISK_ALERT_THRESHOLD * 0.3:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {
        "vulnerability_score": vuln_score,
        "exposure_score": exposure_score,
        "privilege_score": privilege_score,
        "runtime_anomaly": is_runtime_anomaly,
        "total_score": round(total, 2),
        "severity_label": label,
    }


def build_exploit_chain_explanation(container_name, risk, config_findings, vuln_findings):
    """
    Human-readable justification for *why* something scored the way it did —
    the "graph-based correlation" story used in the exploit path narrative.
    """
    reasons = []
    if risk["vulnerability_score"] >= SEVERITY_WEIGHTS["HIGH"]:
        reasons.append(f"has a HIGH/CRITICAL severity vulnerability ({len(vuln_findings)} CVE(s) found)")
    if risk["exposure_score"] >= EXPOSURE_WEIGHTS["internet"]:
        reasons.append("is exposed to the public internet")
    if risk["privilege_score"] >= PRIVILEGE_WEIGHTS["root"]:
        reasons.append("runs with root or privileged access")
    if risk["runtime_anomaly"]:
        reasons.append("is currently exhibiting abnormal runtime behavior")
    if config_findings:
        reasons.append(f"has {len(config_findings)} configuration misconfiguration(s)")

    if not reasons:
        return f"{container_name}: no significant risk factors correlated."

    joined = ", ".join(reasons)
    return f"{container_name} is {risk['severity_label']} risk because it {joined}."
