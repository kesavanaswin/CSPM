"""
engines/mitigation_engine.py
------------------------------
Layer 3: MITIGATION ENGINE

Consumes RiskAssessment objects and:
    1. Generates structured Alert records (console + JSON log at
       output/alerts.json).
    2. Simulates a Kubernetes Admission Controller: containers whose
       risk classification is "Critical" are BLOCKED from admission
       (mirroring a real ValidatingAdmissionWebhook denying the pod).
       "High" risk containers are ALLOWED but flagged for review.
    3. Emits a simulated Slack/webhook-style notification payload for
       High/Critical findings, printed to console and saved to disk
       (no real network call is made -- this keeps the project
       self-contained and safe to run anywhere).
"""

from datetime import datetime, timezone
from typing import List

from storage.json_store import JSONStore
from utils.logger import get_logger
from utils.models import RiskAssessment, Alert

logger = get_logger("engines.mitigation")

_BLOCK_THRESHOLD = "Critical"
_FLAG_THRESHOLDS = {"High", "Critical"}


class MitigationEngine:
    def __init__(self, alerts_output_path: str, webhook_output_path: str):
        self.alerts_output_path = alerts_output_path
        self.webhook_output_path = webhook_output_path
        self._admission_log: List[dict] = []

    # ------------------------------------------------------------------
    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def admission_decision(self, assessment: RiskAssessment) -> str:
        """
        Simulated Kubernetes ValidatingAdmissionWebhook decision.
        Returns 'BLOCKED' or 'ALLOWED'.
        """
        if assessment.classification == _BLOCK_THRESHOLD:
            decision = "BLOCKED"
            logger.critical(
                f"[ADMISSION CONTROLLER] {assessment.container_id} "
                f"DENIED admission (risk={assessment.normalized_score}/100, "
                f"classification={assessment.classification})."
            )
        else:
            decision = "ALLOWED"
            logger.info(
                f"[ADMISSION CONTROLLER] {assessment.container_id} "
                f"admitted to cluster (risk={assessment.normalized_score}/100)."
            )
        self._admission_log.append(
            {
                "container_id": assessment.container_id,
                "decision": decision,
                "risk_score": assessment.normalized_score,
                "classification": assessment.classification,
                "timestamp": self._timestamp(),
            }
        )
        return decision

    def build_alert(self, assessment: RiskAssessment, action_taken: str) -> Alert:
        summary = (
            f"Container '{assessment.container_id}' classified {assessment.classification} "
            f"with unified risk score {assessment.normalized_score}/100 "
            f"(vuln={assessment.vulnerability_score} x priv={assessment.privilege_score} "
            f"x exposure={assessment.exposure_score})."
        )
        alert = Alert(
            container_id=assessment.container_id,
            classification=assessment.classification,
            risk_score=assessment.normalized_score,
            summary=summary,
            factors=assessment.contributing_factors,
            action_taken=action_taken,
            timestamp=self._timestamp(),
        )
        return alert

    def dispatch_notification(self, alert: Alert) -> dict:
        """
        Builds a Slack/webhook-style JSON payload for High/Critical
        alerts. No real HTTP request is sent -- printed + persisted
        to output/webhook_notifications.json for inspection, exactly
        the shape you'd POST to a real Slack incoming-webhook URL.
        """
        payload = {
            "text": (
                f":rotating_light: *{alert.classification} risk detected* "
                f"in `{alert.container_id}`\n"
                f"Score: *{alert.risk_score}/100*\n"
                f"Action: *{alert.action_taken}*\n"
                f"Factors: {', '.join(alert.factors)}"
            ),
            "container_id": alert.container_id,
            "classification": alert.classification,
            "risk_score": alert.risk_score,
            "timestamp": alert.timestamp,
        }
        logger.warning(f"[NOTIFY] Slack/webhook alert dispatched for {alert.container_id}: "
                        f"{alert.classification} ({alert.risk_score}/100)")
        JSONStore.append(self.webhook_output_path, payload)
        return payload

    # ------------------------------------------------------------------
    def process(self, assessment: RiskAssessment) -> Alert:
        """Full mitigation pipeline for a single container's risk assessment."""
        decision = self.admission_decision(assessment)
        action_taken = "BLOCKED_BY_ADMISSION_CONTROLLER" if decision == "BLOCKED" else "ALLOWED_FLAGGED_FOR_REVIEW"
        if assessment.classification not in _FLAG_THRESHOLDS:
            action_taken = "ALLOWED_NO_ACTION"

        alert = self.build_alert(assessment, action_taken)
        JSONStore.append(self.alerts_output_path, alert.to_dict())

        if assessment.classification in _FLAG_THRESHOLDS:
            self.dispatch_notification(alert)

        return alert

    def admission_log(self) -> List[dict]:
        return self._admission_log
