"""
utils/models.py
----------------
Shared data models (dataclasses) used across all engines.

Keeping these in one place ensures the Ingestion, Analysis, Risk, and
Mitigation engines all agree on the shape of the data flowing between
them, and gives us free __repr__ / to_dict() support for JSON logging.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class ContainerConfig:
    """Static configuration state of a container (from manifest / docker inspect)."""
    container_id: str
    image: str
    namespace: str = "default"
    privileged: bool = False
    run_as_root: bool = False
    host_network: bool = False
    host_pid: bool = False
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None
    exposed_publicly: bool = False
    environment: str = "production"  # production | staging | development

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VulnFinding:
    cve_id: str
    package: str
    severity: str            # LOW | MEDIUM | HIGH | CRITICAL (source scanner scale)
    fixed_version: Optional[str] = None
    description: str = ""


@dataclass
class VulnScanResult:
    """Trivy/Grype-like vulnerability scan output for a single image."""
    container_id: str
    image: str
    findings: List[VulnFinding] = field(default_factory=list)
    scanned_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def max_severity_score(self) -> int:
        """Map the worst finding to a 1-10 numeric severity for risk scoring."""
        scale = {"LOW": 2, "MEDIUM": 4, "HIGH": 7, "CRITICAL": 10}
        if not self.findings:
            return 0
        return max(scale.get(f.severity.upper(), 0) for f in self.findings)


@dataclass
class RuntimeEvent:
    """A single simulated eBPF / Falco runtime telemetry event."""
    container_id: str
    event_type: str          # e.g. process_spawn, file_write, network_connect
    detail: str
    syscall: Optional[str] = None
    timestamp: str = ""
    suspicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MisconfigFinding:
    container_id: str
    rule_id: str
    description: str
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL


@dataclass
class AnomalyResult:
    container_id: str
    is_anomalous: bool
    anomaly_score: float
    method: str
    details: str = ""


@dataclass
class RiskAssessment:
    container_id: str
    vulnerability_score: int
    privilege_score: int
    exposure_score: int
    raw_risk_score: float
    normalized_score: float
    classification: str
    contributing_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    container_id: str
    classification: str
    risk_score: float
    summary: str
    factors: List[str]
    action_taken: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
