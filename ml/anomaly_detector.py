"""
Runtime Anomaly Detector
------------------------
Applies an unsupervised ML model (Isolation Forest by default, One-Class
SVM optional) to per-container syscall frequency vectors to establish a
behavioral baseline and flag deviations, per the project's Phase 3
requirement.

Returns a normalized anomaly score in [0, 1] per container, where 1 means
"far outside the learned normal baseline."
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM


SYSCALL_KEYS = ["open", "connect", "execve", "write"]


def _vectorize(freq_dicts):
    """Convert list of {'open': n, 'connect': n, ...} dicts into an ndarray."""
    return np.array([[fd.get(k, 0) for k in SYSCALL_KEYS] for fd in freq_dicts])


class AnomalyDetector:
    def __init__(self, config):
        ml_cfg = config["analysis"]["ml"]
        self.model_type = ml_cfg.get("model", "isolation_forest")
        self.contamination = ml_cfg.get("contamination", 0.05)
        self.min_samples = ml_cfg.get("min_samples_to_train", 20)

    def _build_model(self):
        if self.model_type == "one_class_svm":
            return OneClassSVM(nu=self.contamination, kernel="rbf", gamma="scale")
        return IsolationForest(contamination=self.contamination, random_state=42)

    def score_container(self, syscall_history):
        """
        syscall_history: list of {'open': n, 'connect': n, 'execve': n, 'write': n}
        dicts representing successive time-window observations for one container.

        Returns anomaly_score in [0,1] for the *latest* observation relative
        to the container's own history baseline.
        """
        if len(syscall_history) < 3:
            # Not enough data to establish a baseline; treat as unknown/neutral.
            return 0.0

        X = _vectorize(syscall_history)
        model = self._build_model()
        model.fit(X)

        # decision_function: higher = more normal, lower/negative = more anomalous.
        raw_scores = model.decision_function(X)
        latest_raw = raw_scores[-1]

        # Normalize to [0, 1] using min-max over this container's own score
        # distribution, then invert so 1 = most anomalous.
        smin, smax = raw_scores.min(), raw_scores.max()
        if smax == smin:
            return 0.0
        normalized = (latest_raw - smin) / (smax - smin)
        anomaly_score = 1.0 - normalized
        return round(float(np.clip(anomaly_score, 0.0, 1.0)), 3)

    def score_all(self, events_by_container: dict):
        """events_by_container: {container_id: [syscall_freq, ...]}"""
        return {cid: self.score_container(hist) for cid, hist in events_by_container.items()}
