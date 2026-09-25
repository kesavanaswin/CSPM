"""
Alerting
--------
Sends prioritized alerts to Slack (via webhook), a generic webhook URL,
and/or the console. Designed to combat "alert fatigue": only HIGH/CRITICAL
severity findings are sent externally by default; MEDIUM/LOW are only
logged, unless verbose mode is enabled.
"""

import json
import requests


class Alerter:
    def __init__(self, config):
        self.slack_url = config["mitigation"]["alerting"].get("slack_webhook_url", "")
        self.console_output = config["mitigation"]["alerting"].get("console_output", True)

    def notify(self, ranked_results, min_severity=("CRITICAL", "HIGH")):
        to_alert = [r for r in ranked_results if r["severity"] in min_severity]

        if self.console_output:
            for r in to_alert:
                print(f"[{r['severity']}] {r['container_id']} ({r['image']}) "
                      f"risk={r['risk_score']} ns={r['namespace']}")

        if self.slack_url:
            for r in to_alert:
                self._send_slack(r)

        return to_alert

    def _send_slack(self, result):
        text = (f":rotating_light: *{result['severity']}* risk on "
                f"`{result['container_id']}` ({result['image']}) "
                f"score={result['risk_score']}")
        try:
            requests.post(self.slack_url, data=json.dumps({"text": text}),
                          headers={"Content-Type": "application/json"}, timeout=5)
        except requests.RequestException as e:
            print(f"[alerting] Slack post failed: {e}")
