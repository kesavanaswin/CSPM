"""
Kubernetes State Reader
------------------------
LIVE mode: would call the Kubernetes API server (via `kubectl` or the
official python client) to list running pods/containers and their specs.
DEMO mode: reads pre-recorded sample_data/k8s_manifests.json.
"""

import json


class K8sStateReader:
    def __init__(self, config):
        self.mode = config["mode"]
        self.demo_path = "sample_data/k8s_manifests.json"

    def get_containers(self):
        if self.mode == "live":
            return self._get_live()
        return self._get_demo()

    def _get_demo(self):
        with open(self.demo_path) as f:
            data = json.load(f)
        return data["containers"]

    def _get_live(self):
        # Placeholder: in a real deployment this would use the kubernetes
        # python client (`from kubernetes import client, config`) to list
        # pods across namespaces and extract securityContext, resources,
        # and hostNetwork/hostPID fields from each container spec.
        raise NotImplementedError(
            "Live K8s integration requires cluster credentials. "
            "Configure a kubeconfig and implement via the kubernetes python client."
        )
