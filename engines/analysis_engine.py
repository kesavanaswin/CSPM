"""
engines/analysis_engine.py
----------------------------
Layer 2: ANALYSIS ENGINE

Two responsibilities:

    A. Policy-as-Code Engine (OPA/Rego-style)
       Evaluates each container's static configuration against the
       declarative rule set in config/policies.yaml. Rules are scoped
       per-environment, simulating the "dynamic policy-as-code generator"
       idea (production is held to stricter rules than dev/staging).

    B. Runtime Anomaly Detection
       Aggregates per-container runtime events into simple behavioral
       features (syscall/event-type frequencies) and flags outliers.
       Uses scikit-learn's IsolationForest when available; otherwise
       falls back to a transparent statistical z-score / rule heuristic,
       so the framework keeps working without the optional ML dependency.
"""

from collections import defaultdict
from typing import List, Dict
import os

import yaml

from utils.logger import get_logger
from utils.models import ContainerConfig, MisconfigFinding, RuntimeEvent, AnomalyResult

logger = get_logger("engines.analysis")

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:  # pragma: no cover
    _HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest
    _HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    _HAS_SKLEARN = False


class PolicyEngine:
    """Evaluates container configurations against policy-as-code rules."""

    _OPERATORS = {
        "equals": lambda actual, expected: actual == expected,
        "not_equals": lambda actual, expected: actual != expected,
        "is_empty": lambda actual, expected: (not actual) == expected,
    }

    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.rules = []
        self.environment_multipliers = {}
        self._load_policies()

    def _load_policies(self):
        if not os.path.exists(self.policy_path):
            logger.critical(f"Policy file not found: {self.policy_path}")
            return
        with open(self.policy_path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        self.rules = doc.get("rules", [])
        self.environment_multipliers = doc.get("environment_multipliers", {})
        logger.info(f"Loaded {len(self.rules)} policy rule(s) from {self.policy_path}.")

    def evaluate(self, container: ContainerConfig) -> List[MisconfigFinding]:
        findings: List[MisconfigFinding] = []
        for rule in self.rules:
            envs = rule.get("environments", [])
            if envs and container.environment not in envs:
                continue  # rule not applicable in this deployment environment

            field = rule["field"]
            operator = rule["operator"]
            expected = rule["value"]
            actual = getattr(container, field, None)

            op_fn = self._OPERATORS.get(operator)
            if op_fn is None:
                logger.warning(f"Unknown policy operator '{operator}' in rule {rule.get('id')}")
                continue

            if op_fn(actual, expected):
                findings.append(
                    MisconfigFinding(
                        container_id=container.container_id,
                        rule_id=rule["id"],
                        description=rule["description"],
                        severity=rule["severity"],
                    )
                )
                logger.warning(
                    f"[{container.container_id}] Policy violation {rule['id']}: {rule['description']}"
                )
        if not findings:
            logger.info(f"[{container.container_id}] No policy violations detected.")
        return findings

    def get_environment_multiplier(self, environment: str) -> float:
        return self.environment_multipliers.get(environment, 1.0)


class AnomalyDetector:
    """
    Lightweight runtime anomaly detection over aggregated container
    behavior. Builds a small feature vector per container:
        [suspicious_event_ratio, total_events, distinct_event_types]
    and flags containers whose behavior deviates from the population.
    """

    def __init__(self, contamination: float = 0.25):
        self.contamination = contamination  # expected proportion of anomalous containers
        self.method = "IsolationForest" if (_HAS_SKLEARN and _HAS_NUMPY) else "StatisticalZScore"
        logger.info(f"AnomalyDetector initialized using method: {self.method}")

    @staticmethod
    def _build_features(events_by_container: Dict[str, List[RuntimeEvent]]) -> Dict[str, List[float]]:
        features = {}
        for cid, events in events_by_container.items():
            total = len(events)
            suspicious = sum(1 for e in events if e.suspicious)
            distinct_types = len({e.event_type for e in events})
            ratio = suspicious / total if total else 0.0
            features[cid] = [ratio, float(total), float(distinct_types)]
        return features

    def analyze(self, runtime_events: List[RuntimeEvent]) -> Dict[str, AnomalyResult]:
        events_by_container: Dict[str, List[RuntimeEvent]] = defaultdict(list)
        for e in runtime_events:
            events_by_container[e.container_id].append(e)

        feature_map = self._build_features(events_by_container)
        results: Dict[str, AnomalyResult] = {}

        if not feature_map:
            logger.info("No runtime events available for anomaly analysis.")
            return results

        if self.method == "IsolationForest" and len(feature_map) >= 2:
            results = self._analyze_isolation_forest(feature_map)
        else:
            results = self._analyze_statistical(feature_map)

        for cid, res in results.items():
            if res.is_anomalous:
                logger.warning(f"[{cid}] Runtime anomaly detected (score={res.anomaly_score:.2f}) via {res.method}.")
            else:
                logger.info(f"[{cid}] Runtime behavior within normal baseline (score={res.anomaly_score:.2f}).")
        return results

    def _analyze_isolation_forest(self, feature_map: Dict[str, List[float]]) -> Dict[str, AnomalyResult]:
        ids = list(feature_map.keys())
        X = np.array([feature_map[cid] for cid in ids])

        model = IsolationForest(
            n_estimators=100,
            contamination=min(self.contamination, 0.5),
            random_state=42,
        )
        model.fit(X)
        raw_scores = model.decision_function(X)  # higher = more normal
        predictions = model.predict(X)  # -1 = anomaly, 1 = normal

        results = {}
        for cid, raw_score, pred in zip(ids, raw_scores, predictions):
            # Invert & normalize so higher anomaly_score = more anomalous, roughly 0-1
            normalized = max(0.0, min(1.0, (0.5 - raw_score)))
            results[cid] = AnomalyResult(
                container_id=cid,
                is_anomalous=(pred == -1),
                anomaly_score=float(normalized),
                method="IsolationForest",
                details=f"features(susp_ratio, total_events, distinct_types)={feature_map[cid]}",
            )
        return results

    def _analyze_statistical(self, feature_map: Dict[str, List[float]]) -> Dict[str, AnomalyResult]:
        """
        Fallback heuristic when sklearn/numpy are unavailable or the
        sample is too small for IsolationForest to be meaningful:
        flags a container as anomalous if its suspicious-event ratio
        exceeds a fixed threshold, OR it deviates > 1.5 std-dev from
        the population mean ratio.
        """
        ratios = [v[0] for v in feature_map.values()]
        mean_ratio = sum(ratios) / len(ratios)
        variance = sum((r - mean_ratio) ** 2 for r in ratios) / len(ratios)
        std_dev = variance ** 0.5

        results = {}
        for cid, feats in feature_map.items():
            ratio = feats[0]
            z_score = (ratio - mean_ratio) / std_dev if std_dev > 0 else 0.0
            is_anomalous = ratio >= 0.3 or z_score >= 1.5
            results[cid] = AnomalyResult(
                container_id=cid,
                is_anomalous=is_anomalous,
                anomaly_score=round(min(1.0, ratio + max(0.0, z_score) * 0.1), 3),
                method="StatisticalZScore",
                details=f"suspicious_ratio={ratio:.2f}, z_score={z_score:.2f}",
            )
        return results
