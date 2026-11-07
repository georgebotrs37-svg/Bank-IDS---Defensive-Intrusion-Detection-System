import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple
from sklearn.ensemble import IsolationForest


class TransactionAnomalyDetector:
    """
    Unsupervised Machine Learning Anomaly Detector using Scikit-Learn's Isolation Forest.
    Evaluates multi-dimensional financial features:
    1. Transaction Amount
    2. Transaction Hour (Circadian deviation)
    3. Account Velocity (rolling transaction count)
    4. Destination novelty score
    """
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42
        )
        self.is_fitted = False
        self._init_baseline_model()

    def _init_baseline_model(self):
        """Fit with synthetic normal banking transaction distributions to provide instant baseline."""
        np.random.seed(42)
        n_samples = 1200
        
        # Normal retail banking amounts: lognormal distribution (mean $150, std $300)
        amounts = np.random.lognormal(mean=4.8, sigma=1.2, size=n_samples)
        amounts = np.clip(amounts, 10.0, 15000.0)
        
        # Normal transaction hours: concentrated during daytime 08:00 - 21:00
        hours = np.random.normal(loc=14.0, scale=3.5, size=n_samples)
        hours = np.clip(hours, 0, 23)
        
        # Velocity in last 5 minutes: mostly 1 to 2
        velocities = np.random.choice([1, 1, 1, 2, 2, 3], size=n_samples)
        
        # Weekend indicator (0 or 1)
        is_weekend = np.random.choice([0, 1], size=n_samples, p=[0.75, 0.25])

        X = np.column_stack([amounts, hours, velocities, is_weekend])
        self.model.fit(X)
        self.is_fitted = True

    def extract_features(self, log_entry: Any, recent_tx_count: int = 1) -> np.ndarray:
        amount = float(getattr(log_entry, "amount", 0.0) or 0.0)
        ts = getattr(log_entry, "timestamp", None)
        hour = ts.hour if ts else 12
        is_weekend = 1 if (ts and ts.weekday() >= 5) else 0
        velocity = max(1, recent_tx_count)

        return np.array([[amount, hour, velocity, is_weekend]])

    def predict(self, log_entry: Any, recent_tx_count: int = 1) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Returns:
            is_anomaly (bool): True if flagged as an outlier
            anomaly_score (float): Normalized risk score between 0.0 and 100.0
            breakdown (dict): Explainable factors driving the score
        """
        feats = self.extract_features(log_entry, recent_tx_count)
        raw_pred = self.model.predict(feats)[0]  # -1 for anomaly, 1 for normal
        decision_val = self.model.decision_function(feats)[0]  # Lower means more abnormal

        # Normalize decision function to 0-100 score (lower raw decision means higher anomaly score)
        # typical decision_function ranges from -0.3 (extreme anomaly) to +0.25 (typical normal)
        normalized_score = max(0.0, min(100.0, float((0.2 - decision_val) * 160.0)))

        is_anomaly = bool((raw_pred == -1) or (normalized_score >= 70.0))

        amount = float(getattr(log_entry, "amount", 0.0) or 0.0)
        ts = getattr(log_entry, "timestamp", None)
        hour = ts.hour if ts else 12

        breakdown = {
            "amount": amount,
            "hour_of_day": hour,
            "velocity": recent_tx_count,
            "isolation_score": round(float(decision_val), 4),
            "normalized_risk_score": round(normalized_score, 1),
            "is_outlier": is_anomaly
        }

        return is_anomaly, normalized_score, breakdown
