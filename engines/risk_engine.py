"""
engines/risk_engine.py
------------------------
Layer 2b (Correlation) / Core research contribution: RISK SCORING ENGINE

Implements the unified, context-aware risk formula:

    Risk = Vulnerability Severity x Privilege Level x Exposure Level

Where:
    Vulnerability Severity (1-10) : worst CVE severity from the vuln scan
    Privilege Level (1-3)         : derived from policy-as-code misconfig findings
                                     (privileged / root / host namespaces)
    Exposure Level (1-3)          : derived from public exposure + runtime
                                     anomaly signal (an internet-facing container
                                     actively exhibiting suspicious behavior is
                                     the highest-exposure case)

This is the "correlation engine": a standalone vulnerability or
misconfiguration is low risk in isolation, but the multiplicative
formula ensures that containers where vulnerability + privilege +
exposure compound together are escalated sharply, matching the
academic "attack path" framing from the project brief.
"""

from typing import List, Dict

from utils.logger import get_logger
from utils.models import (
    ContainerConfig,
    VulnScanResult,
    MisconfigFinding,
    AnomalyResult,
    RiskAssessment,
)

logger = get_logger("engines.risk")

# Classification thresholds on the normalized 0-100 scale.
_THRESHOLDS = [
    (85, "Critical"),
    (60, "High"),
    (30, "Medium"),
    (0, "Low"),
]

_MAX_RAW_SCORE = 10 * 3 * 3  # vuln(10) * privilege(3) * exposure(3) = 90


class RiskEngine:
    def __init__(self, environment_multipliers: Dict[str, float] = None):
        self.environment_multipliers = environment_multipliers or {}

    # ------------------------------------------------------------------
    def _privilege_score(self, misconfigs: List[MisconfigFinding]) -> (int, List[str]):
        """
        Privilege Level 1-3, derived from the most severe active
        misconfiguration touching container privilege boundaries.
        """
        factors = []
        if not misconfigs:
            return 1, factors

        severity_rank = {"CRITICAL": 3, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        score = 1
        for m in misconfigs:
            factors.append(f"{m.rule_id}:{m.severity}")
            score = max(score, severity_rank.get(m.severity.upper(), 1))
        return score, factors

    def _exposure_score(self, container: ContainerConfig, anomaly: AnomalyResult = None) -> (int, List[str]):
        """
        Exposure Level 1-3:
            1 = internal only, no anomalous runtime behavior
            2 = public exposure OR active anomaly (not both)
            3 = public exposure AND active anomalous runtime behavior
        """
        factors = []
        publicly_exposed = container.exposed_publicly
        is_anomalous = bool(anomaly and anomaly.is_anomalous)

        if publicly_exposed:
            factors.append("publicly_exposed")
        if is_anomalous:
            factors.append(f"runtime_anomaly(score={anomaly.anomaly_score:.2f})")

        if publicly_exposed and is_anomalous:
            return 3, factors
        if publicly_exposed or is_anomalous:
            return 2, factors
        return 1, factors

    def _classify(self, normalized_score: float) -> str:
        for threshold, label in _THRESHOLDS:
            if normalized_score >= threshold:
                return label
        return "Low"

    # ------------------------------------------------------------------
    def assess(
        self,
        container: ContainerConfig,
        vuln_result: VulnScanResult = None,
        misconfigs: List[MisconfigFinding] = None,
        anomaly: AnomalyResult = None,
    ) -> RiskAssessment:
        misconfigs = misconfigs or []

        vuln_score = vuln_result.max_severity_score() if vuln_result else 0
        # A container with zero known CVEs still carries a nominal baseline
        # so that severe misconfig + exposure alone can still register risk.
        vuln_score_effective = max(vuln_score, 1)

        privilege_score, priv_factors = self._privilege_score(misconfigs)
        exposure_score, exp_factors = self._exposure_score(container, anomaly)

        raw_score = vuln_score_effective * privilege_score * exposure_score

        env_multiplier = self.environment_multipliers.get(container.environment, 1.0)
        adjusted_score = raw_score * env_multiplier

        normalized = min(100.0, round((adjusted_score / _MAX_RAW_SCORE) * 100, 2))
        classification = self._classify(normalized)

        factors = []
        if vuln_result and vuln_result.findings:
            worst = max(vuln_result.findings, key=lambda f: vuln_score)
            factors.append(f"vulnerability:max_severity={vuln_score}")
        factors.extend(priv_factors)
        factors.extend(exp_factors)
        factors.append(f"environment={container.environment}(x{env_multiplier})")

        assessment = RiskAssessment(
            container_id=container.container_id,
            vulnerability_score=vuln_score_effective,
            privilege_score=privilege_score,
            exposure_score=exposure_score,
            raw_risk_score=raw_score,
            normalized_score=normalized,
            classification=classification,
            contributing_factors=factors,
        )

        logger.info(
            f"[{container.container_id}] Risk={normalized}/100 ({classification}) "
            f"[vuln={vuln_score_effective} x priv={privilege_score} x exp={exposure_score}, "
            f"env_x{env_multiplier}]"
        )
        return assessment
