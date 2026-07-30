"""
Phase 2: Vulnerability / Dependency Scanning (Image State)

Wraps the Trivy CLI to scan a container image for known CVEs.
Implements simple delta-scanning: previously-seen image digests are cached
so unchanged images are skipped on repeat scans, keeping the framework
lightweight as described in the synopsis.
"""

import json
import os
import shutil
import subprocess

from config import TRIVY_BINARY, TRIVY_SEVERITY, BASE_DIR

SCAN_CACHE_FILE = os.path.join(BASE_DIR, "samples", "scan_cache.json")


def _trivy_available():
    return shutil.which(TRIVY_BINARY) is not None


def _load_cache():
    if os.path.exists(SCAN_CACHE_FILE):
        with open(SCAN_CACHE_FILE) as f:
            return json.load(f)
    return {}


def _save_cache(cache):
    os.makedirs(os.path.dirname(SCAN_CACHE_FILE), exist_ok=True)
    with open(SCAN_CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def get_image_digest(image):
    """Resolve the image to a content digest so we can detect unchanged images."""
    if shutil.which("docker") is None:
        return image  # docker not available in this environment; use tag as-is
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return image  # fall back to the tag itself if digest lookup fails


def scan_image(image, force=False):
    """
    Scan `image` with Trivy. Skips the scan (delta-scanning) if the image's
    digest is unchanged since the last scan, unless force=True.
    Returns a list of dicts: cve_id, package, installed_version, fixed_version, severity.
    """
    cache = _load_cache()
    digest = get_image_digest(image)

    if not force and cache.get(image) == digest:
        return {"skipped": True, "reason": "unchanged image digest", "findings": []}

    if not _trivy_available():
        return {"skipped": True, "reason": "trivy binary not found on PATH", "findings": []}

    proc = subprocess.run(
        [
            TRIVY_BINARY, "image",
            "--severity", TRIVY_SEVERITY,
            "--format", "json",
            "--quiet",
            image,
        ],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"trivy scan failed: {proc.stderr}")

    report = json.loads(proc.stdout)
    findings = []
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "cve_id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion", ""),
                "severity": vuln.get("Severity", "UNKNOWN"),
            })

    cache[image] = digest
    _save_cache(cache)

    return {"skipped": False, "reason": None, "findings": findings}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python vuln_scan.py <image:tag> [--force]")
        sys.exit(1)
    image = sys.argv[1]
    force = "--force" in sys.argv
    result = scan_image(image, force=force)
    if result["skipped"]:
        print(f"Scan skipped: {result['reason']}")
    else:
        for f in result["findings"]:
            print(f"[{f['severity']}] {f['cve_id']} in {f['package']} "
                  f"(installed={f['installed_version']}, fixed={f['fixed_version']})")
