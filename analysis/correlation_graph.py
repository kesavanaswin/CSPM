"""
Correlation Engine
------------------
Builds a per-container graph node that unifies signals from all three
ingestion sources (vulnerability scan, OPA policy violations, runtime
anomaly score) plus static exposure/privilege facts. This unified node
is what makes the risk scoring "context-aware" rather than three
disconnected dashboards, per the project's academic novelty goal.

A NetworkX graph is also built connecting containers that share an
exploitable path (e.g. same namespace + both internet-exposed) so an
"attack path map" can be rendered, per Phase 4 / research requirements.
"""

import networkx as nx


EXPOSURE_SCORES = {
    "public_loadbalancer": 1.0,
    "cluster_internal": 0.6,
    "internal_only": 0.1,
}


def _privilege_score(container):
    if container.get("privileged") is True or container.get("runAsRoot") is True:
        return 1.0
    if container.get("capabilities_added"):
        return 0.5
    return 0.1


def _worst_cvss(vulns):
    if not vulns:
        return 0.0
    return max(v.get("cvss", 0.0) for v in vulns)


class CorrelationEngine:
    def __init__(self):
        self.graph = nx.Graph()

    def build_container_profile(self, container, vuln_result, opa_violations, anomaly_score):
        """Merge all signal sources into one unified profile dict per container."""
        cid = container["container_id"]
        profile = {
            "container_id": cid,
            "pod": container.get("pod"),
            "namespace": container.get("namespace"),
            "image": container.get("image"),
            "vulnerability_score": round(_worst_cvss(vuln_result.get("vulnerabilities", [])) / 10.0, 3),
            "worst_cve": max(
                vuln_result.get("vulnerabilities", []),
                key=lambda v: v.get("cvss", 0), default=None
            ),
            "privilege_score": _privilege_score(container),
            "exposure_score": EXPOSURE_SCORES.get(container.get("exposure"), 0.1),
            "anomaly_score": anomaly_score,
            "opa_violations": opa_violations,
        }
        self.graph.add_node(cid, **profile)
        return profile

    def link_related_containers(self, containers):
        """Connect containers sharing a namespace and both exposed externally,
        as a simple proxy for a shared attack surface / lateral movement path."""
        for i, c1 in enumerate(containers):
            for c2 in containers[i + 1:]:
                same_ns = c1.get("namespace") == c2.get("namespace")
                both_exposed = (
                    c1.get("exposure") in ("public_loadbalancer", "cluster_internal")
                    and c2.get("exposure") in ("public_loadbalancer", "cluster_internal")
                )
                if same_ns and both_exposed:
                    self.graph.add_edge(
                        c1["container_id"], c2["container_id"],
                        reason=f"shared namespace '{c1.get('namespace')}' + both network-exposed"
                    )

    def attack_paths(self):
        """Return connected components with 2+ nodes as candidate attack paths."""
        return [list(c) for c in nx.connected_components(self.graph) if len(c) > 1]
