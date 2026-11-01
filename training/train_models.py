
"""
ThreatLens AI - Model Training Engine

Binary models:
1. Logistic Regression
2. Decision Tree
3. Random Forest
4. Support Vector Machine

Multiclass model:
5. Random Forest Malware Family Classifier

Model selection is based on cross-validation F1.
The test set is reserved for final evaluation.
"""

import os
import time
import json
import logging

import joblib
import numpy as np

from sklearn.base import clone
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)

from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_score,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatlens.training")


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "models")

BACKEND_MODELS_DIR = os.path.abspath(
    os.path.join(
        BASE_DIR,
        "..",
        "backend",
        "app",
        "ml",
        "saved_models",
    )
)

RANDOM_STATE = 42
CV_FOLDS = 5


def ensure_directories():
    """Create model output directories."""

    os.makedirs(SAVED_MODELS_DIR, exist_ok=True)
    os.makedirs(BACKEND_MODELS_DIR, exist_ok=True)


def load_array(filename):
    """Load a NumPy array and check that the file exists."""

    path = os.path.join(PROCESSED_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Processed dataset not found: {path}. "
            "Run training/preprocess.py first."
        )

    return np.load(path, allow_pickle=False)


def validate_dataset(
    X_train,
    X_test,
    y_train,
    y_test,
    dataset_name,
):
    """Validate training and test arrays before model fitting."""

    if X_train.ndim != 2 or X_test.ndim != 2:
        raise ValueError(
            f"{dataset_name}: Feature arrays must be two-dimensional."
        )

    if y_train.ndim != 1 or y_test.ndim != 1:
        raise ValueError(
            f"{dataset_name}: Target arrays must be one-dimensional."
        )

    if X_train.shape[0] != len(y_train):
        raise ValueError(
            f"{dataset_name}: Training feature and target counts differ."
        )

    if X_test.shape[0] != len(y_test):
        raise ValueError(
            f"{dataset_name}: Test feature and target counts differ."
        )

    if X_train.shape[1] != X_test.shape[1]:
        raise ValueError(
            f"{dataset_name}: Training and test feature counts differ."
        )

    if X_train.shape[0] == 0 or X_test.shape[0] == 0:
        raise ValueError(
            f"{dataset_name}: Training or test dataset is empty."
        )

    if not np.isfinite(X_train).all():
        raise ValueError(
            f"{dataset_name}: Training data contains invalid numeric values."
        )

    if not np.isfinite(X_test).all():
        raise ValueError(
            f"{dataset_name}: Test data contains invalid numeric values."
        )

    if len(np.unique(y_train)) < 2:
        raise ValueError(
            f"{dataset_name}: Training data must contain at least two classes."
        )

    if set(np.unique(y_train)) != set(np.unique(y_test)):
        raise ValueError(
            f"{dataset_name}: Training and test class labels do not match."
        )


def save_model(model, filename):
    """Save a model in both training and backend model directories."""

    for directory in (
        SAVED_MODELS_DIR,
        BACKEND_MODELS_DIR,
    ):
        path = os.path.join(directory, filename)
        joblib.dump(model, path)

        logger.info("Saved model: %s", path)


def save_metadata(metadata):
    """Save model metadata in both output directories."""

    for directory in (
        SAVED_MODELS_DIR,
        BACKEND_MODELS_DIR,
    ):
        path = os.path.join(
            directory,
            "model_metadata.json",
        )

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                metadata,
                file,
                indent=2,
            )


def evaluate_binary_model(
    model,
    X_train,
    y_train,
    X_test,
    y_test,
    name,
):
    """
    Evaluate a binary classifier.

    Cross-validation F1 is used for model selection.
    The held-out test set is used only for final evaluation.
    """

    print(f"\n--- Evaluating {name} ---")

    class_counts = np.unique(
        y_train,
        return_counts=True,
    )[1]

    if len(class_counts) < 2 or min(class_counts) < CV_FOLDS:
        raise ValueError(
            f"{name}: Each class needs at least {CV_FOLDS} "
            "training records for stratified cross-validation."
        )

    cv = StratifiedKFold(
        n_splits=CV_FOLDS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    # Cross-validation is performed using training data only.
    start_time = time.time()

    cv_scores = cross_val_score(
        clone(model),
        X_train,
        y_train,
        cv=cv,
        scoring="f1",
        n_jobs=-1,
        error_score="raise",
    )

    cv_mean_f1 = float(np.mean(cv_scores))
    cv_std_f1 = float(np.std(cv_scores))

    # Fit final model on the complete training split.
    final_model = clone(model)

    final_model.fit(
        X_train,
        y_train,
    )

    train_time = round(
        time.time() - start_time,
        3,
    )

    # Final evaluation on held-out test data.
    y_pred = final_model.predict(X_test)

    labels = [0, 1]

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels,
    )

    tn, fp, fn, tp = cm.ravel()

    accuracy = float(
        accuracy_score(y_test, y_pred)
    )

    precision = float(
        precision_score(
            y_test,
            y_pred,
            pos_label=1,
            zero_division=0,
        )
    )

    recall = float(
        recall_score(
            y_test,
            y_pred,
            pos_label=1,
            zero_division=0,
        )
    )

    f1 = float(
        f1_score(
            y_test,
            y_pred,
            pos_label=1,
            zero_division=0,
        )
    )

    false_positive_rate = (
        float(fp / (fp + tn))
        if (fp + tn) > 0
        else 0.0
    )

    false_negative_rate = (
        float(fn / (fn + tp))
        if (fn + tp) > 0
        else 0.0
    )

    # Calculate ROC-AUC using the probability for class 1.
    roc_auc = 0.0

    if hasattr(final_model, "predict_proba"):
        classes = list(final_model.classes_)

        if 1 in classes:
            positive_class_index = classes.index(1)

            probabilities = final_model.predict_proba(
                X_test
            )[:, positive_class_index]

            roc_auc = float(
                roc_auc_score(
                    y_test,
                    probabilities,
                )
            )

    print(f"\nResults for {name}:")
    print(f"  Accuracy:          {accuracy:.4f}")
    print(f"  Precision:         {precision:.4f}")
    print(f"  Recall:            {recall:.4f}")
    print(f"  Test F1-score:     {f1:.4f}")
    print(f"  CV F1-score:       {cv_mean_f1:.4f}")
    print(f"  CV F1 std:         {cv_std_f1:.4f}")
    print(f"  ROC-AUC:           {roc_auc:.4f}")
    print(f"  False positive rate: {false_positive_rate:.4f}")
    print(f"  False negative rate: {false_negative_rate:.4f}")
    print(f"  Confusion matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"  Training time:     {train_time}s")

    metrics = {
        "model_name": name,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "cv_mean_f1": round(cv_mean_f1, 4),
        "cv_std_f1": round(cv_std_f1, 4),
        "false_positive_rate": round(
            false_positive_rate,
            4,
        ),
        "false_negative_rate": round(
            false_negative_rate,
            4,
        ),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "matrix": [
                [int(tn), int(fp)],
                [int(fn), int(tp)],
            ],
        },
        "training_time_seconds": train_time,
    }

    return final_model, metrics


def train_binary_models():
    """Train and compare four binary classification algorithms."""

    print("\n" + "=" * 60)
    print("BINARY MALWARE CLASSIFICATION")
    print("=" * 60)

    X_train = load_array("binary_X_train.npy")
    X_test = load_array("binary_X_test.npy")
    y_train = load_array("binary_y_train.npy")
    y_test = load_array("binary_y_test.npy")

    validate_dataset(
        X_train,
        X_test,
        y_train,
        y_test,
        "Binary dataset",
    )

    if set(np.unique(y_train)) != {0, 1}:
        raise ValueError(
            "Binary dataset must use labels 0 and 1."
        )

    print(f"Training data shape: {X_train.shape}")
    print(f"Testing data shape:  {X_test.shape}")

    models = {
        "Logistic_Regression": LogisticRegression(
            max_iter=1000,
            random_state=RANDOM_STATE,
        ),

        "Decision_Tree": DecisionTreeClassifier(
            max_depth=15,
            min_samples_split=5,
            random_state=RANDOM_STATE,
        ),

        "Random_Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),

        "Support_Vector_Machine": SVC(
            probability=True,
            kernel="rbf",
            C=1.0,
            random_state=RANDOM_STATE,
        ),
    }

    results = {}
    trained_models = {}

    best_model_name = None
    best_cv_f1 = -1.0

    for name, model in models.items():
        trained_model, metrics = evaluate_binary_model(
            model,
            X_train,
            y_train,
            X_test,
            y_test,
            name,
        )

        results[name] = metrics
        trained_models[name] = trained_model

        # Save each trained model.
        save_model(
            trained_model,
            f"{name.lower()}.joblib",
        )

        # Select the best model using cross-validation F1,
        # not the held-out test score.
        if metrics["cv_mean_f1"] > best_cv_f1:
            best_cv_f1 = metrics["cv_mean_f1"]
            best_model_name = name

    if best_model_name is None:
        raise RuntimeError(
            "No binary model was successfully trained."
        )

    best_model = trained_models[best_model_name]

    save_model(
        best_model,
        "active_binary_model.joblib",
    )

    print("\n" + "=" * 60)
    print("BEST BINARY MODEL")
    print("=" * 60)

    print(f"Model: {best_model_name}")
    print(f"Cross-validation F1: {best_cv_f1:.4f}")
    print(
        "Held-out test F1:",
        results[best_model_name]["f1_score"],
    )

    return (
        best_model_name,
        results,
        X_train.shape[1],
        len(X_train) + len(X_test),
    )


def train_multiclass_model():
    """Train a Random Forest malware-family classifier."""

    print("\n" + "=" * 60)
    print("MULTICLASS MALWARE FAMILY CLASSIFICATION")
    print("=" * 60)

    multi_X_train = load_array("multi_X_train.npy")
    multi_X_test = load_array("multi_X_test.npy")
    multi_y_train = load_array("multi_y_train.npy")
    multi_y_test = load_array("multi_y_test.npy")

    validate_dataset(
        multi_X_train,
        multi_X_test,
        multi_y_train,
        multi_y_test,
        "Multiclass dataset",
    )

    print(f"Training data shape: {multi_X_train.shape}")
    print(f"Testing data shape:  {multi_X_test.shape}")

    multi_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=25,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    start_time = time.time()

    multi_model.fit(
        multi_X_train,
        multi_y_train,
    )

    training_time = round(
        time.time() - start_time,
        3,
    )

    multi_pred = multi_model.predict(
        multi_X_test
    )

    multi_accuracy = float(
        accuracy_score(
            multi_y_test,
            multi_pred,
        )
    )

    multi_precision = float(
        precision_score(
            multi_y_test,
            multi_pred,
            average="weighted",
            zero_division=0,
        )
    )

    multi_recall = float(
        recall_score(
            multi_y_test,
            multi_pred,
            average="weighted",
            zero_division=0,
        )
    )

    multi_f1 = float(
        f1_score(
            multi_y_test,
            multi_pred,
            average="weighted",
            zero_division=0,
        )
    )

    print("\nMulticlass results:")
    print(f"  Accuracy:  {multi_accuracy:.4f}")
    print(f"  Precision: {multi_precision:.4f}")
    print(f"  Recall:    {multi_recall:.4f}")
    print(f"  F1-score:  {multi_f1:.4f}")
    print(f"  Training time: {training_time}s")

    save_model(
        multi_model,
        "multiclass_family_model.joblib",
    )

    metrics = {
        "model_name": "Random_Forest_Multiclass",
        "accuracy": round(multi_accuracy, 4),
        "precision": round(multi_precision, 4),
        "recall": round(multi_recall, 4),
        "f1_score": round(multi_f1, 4),
        "test_samples": int(len(multi_y_test)),
        "training_time_seconds": training_time,
        "classes": [
            int(value)
            for value in multi_model.classes_
        ],
    }

    return metrics, multi_X_train.shape[1]


def main():
    """Run the complete model training pipeline."""

    ensure_directories()

    print("=" * 60)
    print("THREATLENS AI - MODEL TRAINING")
    print("=" * 60)

    # Train and evaluate binary models.
    (
        best_model_name,
        binary_results,
        binary_feature_count,
        binary_record_count,
    ) = train_binary_models()

    # Train malware-family classifier.
    multiclass_metrics, multiclass_feature_count = (
        train_multiclass_model()
    )

    # Save model metadata.
    metadata = {
        "active_model": best_model_name,
        "active_model_file": "active_binary_model.joblib",
        "version": "1.0.0",
        "dataset_name": (
            "ClaMP Integrated PE Dataset "
            "& DA-Proj Malware Families"
        ),
        "training_records": int(binary_record_count),
        "num_features": int(binary_feature_count),
        "multiclass_num_features": int(
            multiclass_feature_count
        ),
        "binary_class_labels": [0, 1],
        "binary_positive_class": 1,
        "model_selection_metric": "5-fold cross-validation F1",
        "test_set_usage": "Final evaluation only",
        "training_date": time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "models_comparison": binary_results,
        "multiclass_metrics": multiclass_metrics,
    }

    save_metadata(metadata)

    print("\n" + "=" * 60)
    print("TRAINING COMPLETED")
    print("=" * 60)

    print(f"Active binary model: {best_model_name}")
    print("Binary models: 4")
    print("Multiclass models: 1")
    print("Metadata and model files saved successfully.")


if __name__ == "__main__":
    main()
