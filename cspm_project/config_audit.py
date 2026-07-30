"""
Phase 1: Misconfiguration Auditing (Static & Configuration State)

Evaluates Kubernetes Pod/Deployment manifests against Rego policies using OPA.
If the `opa` binary is not installed, falls back to an equivalent pure-Python
rule set so the framework still runs end-to-end in dev/demo environments.
"""

import json
import shutil
import subprocess
import yaml

from config import OPA_BINARY, DEFAULT_POLICY_FILE


def _opa_available():
    return shutil.which(OPA_BINARY) is not None


def load_manifest(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def _pod_spec(manifest):
    """Normalize Pod vs Deployment/StatefulSet manifests to the pod spec."""
    kind = manifest.get("kind", "")
    if kind == "Pod":
        return manifest.get("spec", {})
    # Deployment / StatefulSet / DaemonSet
    return (
        manifest.get("spec", {})
        .get("template", {})
        .get("spec", {})
    )


def audit_with_opa(manifest, policy_file=DEFAULT_POLICY_FILE):
    """Run `opa eval` against the manifest using the given Rego policy file."""
    pod_spec = _pod_spec(manifest)
    proc = subprocess.run(
        [
            OPA_BINARY, "eval",
            "--data", policy_file,
            "--input", "/dev/stdin",
            "--format", "json",
            "data.cspm.container.deny",
        ],
        input=json.dumps(pod_spec).encode(),
        capture_output=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval failed: {proc.stderr.decode()}")

    result = json.loads(proc.stdout.decode())
    findings = []
    try:
        values = result["result"][0]["expressions"][0]["value"]
        findings = list(values) if values else []
    except (KeyError, IndexError, TypeError):
        findings = []
    return findings


def audit_with_python_fallback(manifest):
    """Equivalent checks to container_security.rego, in plain Python."""
    pod_spec = _pod_spec(manifest)
    findings = []
    containers = pod_spec.get("containers", [])

    for c in containers:
        sc = c.get("securityContext", {}) or {}
        name = c.get("name", "unknown")

        if sc.get("privileged") is True:
            findings.append(f"Container is running in privileged mode")

        if sc.get("runAsUser") == 0:
            findings.append(f"Container '{name}' is explicitly running as root (uid 0)")

        if "runAsUser" not in sc and not sc.get("runAsNonRoot"):
            findings.append(f"Container '{name}' does not enforce a non-root user")

        limits = (c.get("resources", {}) or {}).get("limits", {}) or {}
        if "cpu" not in limits:
            findings.append(f"Container '{name}' has no CPU resource limit set")
        if "memory" not in limits:
            findings.append(f"Container '{name}' has no memory resource limit set")

    if pod_spec.get("hostNetwork") is True:
        findings.append("Pod uses hostNetwork: true, exposing it to the host's network namespace")
    if pod_spec.get("hostPID") is True:
        findings.append("Pod uses hostPID: true, exposing it to host process visibility")

    for v in pod_spec.get("volumes", []) or []:
        host_path = (v.get("hostPath") or {}).get("path")
        if host_path == "/var/run/docker.sock":
            findings.append("Pod mounts the Docker socket from the host, a common privilege-escalation path")

    return findings


def audit_manifest(path, policy_file=DEFAULT_POLICY_FILE):
    """
    Public entry point. Returns a list of finding strings for the given
    manifest file, using OPA if available, otherwise the Python fallback.
    """
    manifest = load_manifest(path)
    if _opa_available():
        return audit_with_opa(manifest, policy_file)
    return audit_with_python_fallback(manifest)


def infer_privilege_and_exposure(manifest, k8s_service_type=None):
    """
    Best-effort classification used by the risk engine:
    - privilege: privileged > root > non_root
    - exposure: internet (LoadBalancer/NodePort/Ingress) > cluster > internal
    """
    pod_spec = _pod_spec(manifest)
    privilege = "non_root"
    for c in pod_spec.get("containers", []):
        sc = c.get("securityContext", {}) or {}
        if sc.get("privileged") is True:
            privilege = "privileged"
            break
        if sc.get("runAsUser") == 0:
            privilege = "root"

    exposure = "internal"
    if k8s_service_type in ("LoadBalancer", "NodePort"):
        exposure = "internet"
    elif k8s_service_type == "ClusterIP":
        exposure = "cluster"

    return privilege, exposure


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python config_audit.py <manifest.yaml>")
        sys.exit(1)
    for finding in audit_manifest(sys.argv[1]):
        print(f"[FINDING] {finding}")
