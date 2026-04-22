from sklearn.svm import OneClassSVM
import numpy as np


def getOneClassSVMPrediction(df, X_scaled):
    model_svm = OneClassSVM(kernel="rbf", gamma="auto")
    model_svm.fit(X_scaled)
    df["svm_score"] = model_svm.decision_function(X_scaled)
    threshold = np.percentile(df["svm_score"], 5)

    # df["svm_anomaly"] = model_svm.predict(X_scaled)
    df["svm_anomaly"] = df["svm_score"] < threshold

    return df
