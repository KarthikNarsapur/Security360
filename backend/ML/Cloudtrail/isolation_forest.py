from sklearn.ensemble import IsolationForest
import numpy as np


def getIsolationForestPrediction(df, X_scaled):
    model_isf = IsolationForest(contamination=0.01, max_samples="auto", random_state=42)
    model_isf.fit(X_scaled)
    df["isf_score"] = model_isf.decision_function(X_scaled)

    threshold = np.percentile(df["isf_score"], 5)

    # df["isf_anomaly"] = model_isf.predict(X_scaled)
    df["isf_anomaly"] = df["isf_score"] < threshold

    return df
