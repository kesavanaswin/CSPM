"""
OPA Client
----------
In LIVE mode: sends container manifest data to a running OPA server's REST API
(POST /v1/data/<package>) and collects violations.

In DEMO mode: no OPA server is assumed to be running, so we use a local
Python mirror of the exact same Rego logic defined in policies/*.rego.
This keeps demo mode fully offline while producing identical results to
what OPA would return, so swapping to live mode later requires no changes
to downstream code.
"""

import json
import requests


# ---- Local mirror of policies/*.rego (used only in demo mode) ----
def _eval_privileged(c):
    violations = []
    if c.get("privileged") is True:
        violations.append("Container is running in privileged mode")
    if c.get("runAsRoot") is True:
        violations.append("Container is running as root user")
    return violations


def _eval_resource_limits(c):
    violations = []
    if c.get("resource_limits_set") is False:
        violations.append("Container has no CPU/memory resource limits set")
    return violations


def _eval_host_namespace(c):
    violations = []
    if c.get("hostNetwork") is True:
        violations.append("Container shares the host network namespace (hostNetwork=true)")
    if c.get("hostPID") is True:
        violations.append("Container shares the host PID namespace (hostPID=true)")
    return violations


_LOCAL_POLICIES = [_eval_privileged, _eval_resource_limits, _eval_host_namespace]


class OPAClient:
    def __init__(self, config):
        self.mode = config["mode"]
        self.server_url = config["analysis"]["opa"]["server_url"]

    def evaluate(self, container):
        """Return a list of violation strings for a single container dict."""
        if self.mode == "live":
            return self._evaluate_live(container)
        return self._evaluate_demo(container)

    def _evaluate_demo(self, container):
        violations = []
        for policy_fn in _LOCAL_POLICIES:
            violations.extend(policy_fn(container))
        return violations

    def _evaluate_live(self, container):
        violations = []
        packages = ["cspm/privileged", "cspm/resource_limits", "cspm/host_namespace"]
        for pkg in packages:
            url = f"{self.server_url}/v1/data/{pkg}"
            try:
                resp = requests.post(url, json={"input": container}, timeout=3)
                resp.raise_for_status()
                result = resp.json().get("result", {})
                violations.extend(result.get("violation", []))
            except requests.RequestException as e:
                violations.append(f"[OPA unreachable for {pkg}: {e}]")
        return violations

    def evaluate_all(self, containers):
        """Evaluate a list of containers, return {container_id: [violations]}"""
        return {c["container_id"]: self.evaluate(c) for c in containers}
