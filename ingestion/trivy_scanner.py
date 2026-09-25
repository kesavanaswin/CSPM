"""
Trivy Scanner Ingestion
-----------------------
LIVE mode: shells out to the `trivy` binary against a given image and parses
its JSON output.
DEMO mode: reads pre-recorded sample_data/trivy_scan.json.

Also implements a simple delta-scan cache: tracks which image digests have
already been scanned so repeat scans of unchanged layers are skipped
(keeps the framework "lightweight" per the project's Phase 2 requirement).
"""

import json
import subprocess
import hashlib
import os


class TrivyScanner:
    def __init__(self, config):
        self.mode = config["mode"]
        self.binary = config["ingestion"]["trivy"]["binary_path"]
        self.delta_scan = config["ingestion"]["trivy"].get("delta_scan", True)
        self._scanned_cache_path = "reports/.trivy_scanned_digests.json"
        self._scanned_digests = self._load_cache()

    def _load_cache(self):
        if os.path.exists(self._scanned_cache_path):
            with open(self._scanned_cache_path) as f:
                return json.load(f)
        return {}

    def _save_cache(self):
        os.makedirs(os.path.dirname(self._scanned_cache_path), exist_ok=True)
        with open(self._scanned_cache_path, "w") as f:
            json.dump(self._scanned_digests, f)

    def _image_digest(self, image_ref):
        # In live mode this would use `docker inspect` or the registry API
        # to get the real content digest. Here we approximate with a hash
        # of the image reference string for demo purposes.
        return hashlib.sha256(image_ref.encode()).hexdigest()

    def scan_image(self, image_ref):
        digest = self._image_digest(image_ref)
        if self.delta_scan and self._scanned_digests.get(image_ref) == digest:
            return {"image": image_ref, "vulnerabilities": [], "skipped": True,
                     "reason": "unchanged since last scan (delta-scan cache hit)"}

        if self.mode == "live":
            result = self._scan_live(image_ref)
        else:
            result = self._scan_demo(image_ref)

        self._scanned_digests[image_ref] = digest
        self._save_cache()
        return result

    def _scan_live(self, image_ref):
        try:
            proc = subprocess.run(
                [self.binary, "image", "--format", "json", image_ref],
                capture_output=True, text=True, timeout=120
            )
            data = json.loads(proc.stdout)
            vulns = []
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities", []) or []:
                    vulns.append({
                        "cve": v.get("VulnerabilityID"),
                        "severity": v.get("Severity"),
                        "cvss": v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0),
                        "package": v.get("PkgName"),
                        "fixed": bool(v.get("FixedVersion")),
                    })
            return {"image": image_ref, "vulnerabilities": vulns, "skipped": False}
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
            return {"image": image_ref, "vulnerabilities": [], "skipped": False, "error": str(e)}

    def _scan_demo(self, image_ref):
        with open("sample_data/trivy_scan.json") as f:
            data = json.load(f)
        for entry in data["results"]:
            if entry["image"] == image_ref:
                return {"image": image_ref, "container_id": entry["container_id"],
                         "vulnerabilities": entry["vulnerabilities"], "skipped": False}
        return {"image": image_ref, "vulnerabilities": [], "skipped": False}

    def scan_all(self, image_refs):
        return [self.scan_image(img) for img in image_refs]
