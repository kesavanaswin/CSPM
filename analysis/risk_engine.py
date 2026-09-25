"""
Risk Scoring Engine
-------------------
Implements the unified, context-aware risk formula:

    Risk = w1*V + w2*P + w3*E + w4*A + w5*(V * P * E)

Where V=vulnerability, P=privilege, E=exposure, A=anomaly (all in [0,1]),
each weighted (w1..w5), plus a multiplicative "exploit chain" term so that
a container which is simultaneously vulnerable, privileged, AND exposed
gets a compounding score increase -- capturing the Phase 4 requirement
that combined weaknesses are far more dangerous than the sum of their
parts, while avoiding the fragility of a pure-multiplication formula
(which collapses to ~0 if any single factor is low, even when the other
two indicate serious risk).
"""


class RiskEngine:
    def __init__(self, config):
        w = config["risk_engine"]["weights"]
        self.w_vuln = w["vulnerability"]
        self.w_priv = w["privilege"]
        self.w_exp = w["exposure"]
        self.w_anom = w["anomaly"]
        self.w_chain = w["exploit_chain"]
        self.thresholds = config["risk_engine"]["thresholds"]

    def score(self, profile):
        V = profile["vulnerability_score"]
        P = profile["privilege_score"]
        E = profile["exposure_score"]
        A = profile["anomaly_score"]

        # OPA misconfiguration violations act as a small additive nudge on
        # top of the core formula -- each violation raises P slightly, since
        # a misconfiguration is itself a privilege/attack-surface issue.
        misconfig_bonus = min(len(profile.get("opa_violations", [])) * 0.03, 0.15)

        linear = (self.w_vuln * V) + (self.w_priv * P) + (self.w_exp * E) + (self.w_anom * A)
        chain = self.w_chain * (V * P * E)
        raw_score = linear + chain + misconfig_bonus

        return round(min(raw_score, 1.0), 3)

    def severity(self, score):
        t = self.thresholds
        if score >= t["critical"]:
            return "CRITICAL"
        if score >= t["high"]:
            return "HIGH"
        if score >= t["medium"]:
            return "MEDIUM"
        return "LOW"

    def score_all(self, profiles: dict):
        """profiles: {container_id: profile_dict} -> adds risk_score + severity"""
        results = {}
        for cid, profile in profiles.items():
            s = self.score(profile)
            results[cid] = {**profile, "risk_score": s, "severity": self.severity(s)}
        return results
