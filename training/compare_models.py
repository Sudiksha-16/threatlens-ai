"""
ThreatLens AI - Model Comparison & Evaluation Reporting
Generates comparison plots and detailed JSON summary for all 4 candidate models.
"""

import os
import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "backend", "app", "ml", "evaluation")
SAVED_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

os.makedirs(EVAL_DIR, exist_ok=True)

def generate_comparison_reports():
    meta_path = os.path.join(SAVED_MODELS_DIR, "model_metadata.json")
    if not os.path.exists(meta_path):
        print("Model metadata not found. Run train_models.py first.")
        return

    with open(meta_path, "r") as f:
        meta = json.load(f)

    models_data = meta["models_comparison"]
    
    # 1. Bar Chart: Accuracy, Precision, Recall, F1
    model_names = list(models_data.keys())
    clean_names = [n.replace("_", " ") for n in model_names]
    accuracies = [models_data[m]["accuracy"] for m in model_names]
    precisions = [models_data[m]["precision"] for m in model_names]
    recalls = [models_data[m]["recall"] for m in model_names]
    f1_scores = [models_data[m]["f1_score"] for m in model_names]

    x = np.arange(len(model_names))
    width = 0.2

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - 1.5 * width, accuracies, width, label='Accuracy', color='#38D6C5')
    ax.bar(x - 0.5 * width, precisions, width, label='Precision', color='#668CFF')
    ax.bar(x + 0.5 * width, recalls, width, label='Recall', color='#F5B84B')
    ax.bar(x + 1.5 * width, f1_scores, width, label='F1-Score', color='#35C98A')

    ax.set_ylabel('Score (0 - 1.0)')
    ax.set_title('ThreatLens AI - Machine Learning Model Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(clean_names)
    ax.set_ylim(0.9, 1.01)
    ax.legend(loc='lower right')
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout()
    chart_path = os.path.join(EVAL_DIR, "model_comparison.png")
    plt.savefig(chart_path, dpi=200)
    plt.close()
    print(f"Saved comparison chart to {chart_path}")

    # 2. Confusion Matrix Heatmaps
    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    axes = axes.flatten()

    for idx, (m_key, m_val) in enumerate(models_data.items()):
        cm = m_val["confusion_matrix"]["matrix"]
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=axes[idx],
                    xticklabels=["Benign", "Malicious"],
                    yticklabels=["Benign", "Malicious"])
        axes[idx].set_title(f"{m_key.replace('_', ' ')} (Acc: {m_val['accuracy']:.4f})")
        axes[idx].set_ylabel('Actual')
        axes[idx].set_xlabel('Predicted')

    plt.suptitle("Confusion Matrices - 4 Candidate Models", fontsize=14)
    plt.tight_layout()
    cm_path = os.path.join(EVAL_DIR, "confusion_matrices.png")
    plt.savefig(cm_path, dpi=200)
    plt.close()
    print(f"Saved confusion matrices heatmap to {cm_path}")

    # Copy metadata to backend eval dir
    with open(os.path.join(EVAL_DIR, "model_comparison.json"), "w") as f:
        json.dump(models_data, f, indent=2)

    print("Model evaluation artifacts generated successfully.")

if __name__ == "__main__":
    generate_comparison_reports()
