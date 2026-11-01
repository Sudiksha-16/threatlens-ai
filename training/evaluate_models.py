"""
ThreatLens AI - Model Evaluation Script
Computes comprehensive metrics on test data for the active model and candidate models:
Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix.
"""

import os
import json
import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, classification_report
)

PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

def evaluate():
    X_test = np.load(os.path.join(PROCESSED_DIR, "binary_X_test.npy"))
    y_test = np.load(os.path.join(PROCESSED_DIR, "binary_y_test.npy"))

    print(f"Loaded test set with {len(y_test)} samples (Malicious: {sum(y_test)}, Benign: {len(y_test) - sum(y_test)})")

    model_files = {
        "Random Forest (Active)": "random_forest.joblib",
        "Decision Tree": "decision_tree.joblib",
        "Support Vector Machine": "support_vector_machine.joblib",
        "Logistic Regression": "logistic_regression.joblib"
    }

    full_evaluation = {}

    for label, filename in model_files.items():
        filepath = os.path.join(MODELS_DIR, filename)
        if not os.path.exists(filepath):
            continue
        model = joblib.load(filepath)
        y_pred = model.predict(X_test)
        
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))

        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
            roc = float(roc_auc_score(y_test, y_prob))
        else:
            roc = 0.0

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        full_evaluation[label] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        }

        print(f"\n==========================================")
        print(f"Model: {label}")
        print(f"==========================================")
        print(f"Accuracy:  {acc*100:.2f}%")
        print(f"Precision: {prec*100:.2f}%")
        print(f"Recall:    {rec*100:.2f}%")
        print(f"F1-Score:  {f1*100:.2f}%")
        print(f"ROC-AUC:   {roc*100:.2f}%")
        print(f"False Positive Rate: {fpr*100:.2f}% (Clean files flagged as malware)")
        print(f"False Negative Rate: {fnr*100:.2f}% (Malware missed)")
        print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    eval_out = os.path.join(MODELS_DIR, "detailed_evaluation.json")
    with open(eval_out, "w") as f:
        json.dump(full_evaluation, f, indent=2)
    print(f"\nDetailed evaluation written to {eval_out}")

if __name__ == "__main__":
    evaluate()
