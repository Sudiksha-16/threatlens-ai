
"""
ThreatLens AI - Data Preprocessing Pipeline

Handles:
1. Dataset loading and validation
2. Duplicate removal
3. Missing-value inspection and cleaning
4. Categorical feature encoding
5. Stratified train/test splitting
6. Feature scaling
7. Consistent artifact and feature-schema storage

Binary dataset: ClaMP Integrated PE Dataset
Multiclass dataset: DA-Proj Malware Family Dataset
"""

import os
import json
import joblib
import logging

import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatlens.preprocessing")


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(BASE_DIR, "data")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")

BACKEND_PREPROCESS_DIR = os.path.abspath(
    os.path.join(
        BASE_DIR,
        "..",
        "backend",
        "app",
        "ml",
        "preprocessing",
    )
)


RANDOM_STATE = 42
TEST_SIZE = 0.20


def ensure_directories():
    """Create output directories when they do not exist."""

    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(BACKEND_PREPROCESS_DIR, exist_ok=True)


def load_dataset(file_path, encoding=None):
    """Load a CSV dataset and validate that it is not empty."""

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Dataset not found: {file_path}"
        )

    df = pd.read_csv(file_path, encoding=encoding)

    if df.empty:
        raise ValueError(
            f"Dataset is empty: {file_path}"
        )

    logger.info(
        "Loaded %s records from %s",
        len(df),
        os.path.basename(file_path),
    )

    return df


def clean_numeric_features(X, dataset_name):
    """
    Convert feature columns to numeric values.

    Missing or invalid numeric rows are removed instead of silently
    replacing values with zero. This avoids creating misleading
    feature vectors.
    """

    X = X.copy()

    for column in X.columns:
        X[column] = pd.to_numeric(
            X[column],
            errors="coerce",
        )

    missing_before = int(X.isna().sum().sum())

    if missing_before:
        logger.warning(
            "%s contains %s missing or non-numeric feature values.",
            dataset_name,
            missing_before,
        )

        valid_rows = X.notna().all(axis=1)
        removed_rows = int((~valid_rows).sum())

        X = X.loc[valid_rows].copy()

        logger.info(
            "Removed %s rows containing missing or invalid features.",
            removed_rows,
        )

    # Remove rows containing infinite values.
    finite_rows = np.isfinite(
        X.to_numpy(dtype=np.float64)
    ).all(axis=1)

    removed_infinite = int((~finite_rows).sum())

    if removed_infinite:
        X = X.iloc[
            np.flatnonzero(finite_rows)
        ].copy()

        logger.warning(
            "Removed %s rows containing infinite values.",
            removed_infinite,
        )

    if X.empty:
        raise ValueError(
            f"No usable feature records remain in {dataset_name}."
        )

    return X


def save_artifacts(
    scaler,
    encoder,
    feature_names,
    scaler_filename,
    encoder_filename,
    feature_filename,
):
    """Save preprocessing artifacts for training and backend inference."""

    ensure_directories()

    for directory in (
        PROCESSED_DIR,
        BACKEND_PREPROCESS_DIR,
    ):
        joblib.dump(
            scaler,
            os.path.join(directory, scaler_filename),
        )

        joblib.dump(
            encoder,
            os.path.join(directory, encoder_filename),
        )

        with open(
            os.path.join(directory, feature_filename),
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                feature_names,
                file,
                indent=2,
            )


def save_processed_arrays(
    X_train,
    X_test,
    y_train,
    y_test,
    prefix,
):
    """Save processed NumPy arrays for model training."""

    np.save(
        os.path.join(
            PROCESSED_DIR,
            f"{prefix}_X_train.npy",
        ),
        X_train,
    )

    np.save(
        os.path.join(
            PROCESSED_DIR,
            f"{prefix}_X_test.npy",
        ),
        X_test,
    )

    np.save(
        os.path.join(
            PROCESSED_DIR,
            f"{prefix}_y_train.npy",
        ),
        np.asarray(y_train),
    )

    np.save(
        os.path.join(
            PROCESSED_DIR,
            f"{prefix}_y_test.npy",
        ),
        np.asarray(y_test),
    )


def preprocess_binary():
    """Preprocess the ClaMP dataset for benign/malicious classification."""

    print("\n" + "=" * 60)
    print("PREPROCESSING BINARY DATASET (ClaMP)")
    print("=" * 60)

    clamp_path = os.path.join(
        DATA_DIR,
        "clamp_integrated.csv",
    )

    df = load_dataset(clamp_path)

    if "class" not in df.columns:
        raise ValueError(
            "ClaMP dataset must contain a 'class' target column."
        )

    # Remove duplicate records.
    initial_count = len(df)

    df = df.drop_duplicates().copy()

    print(
        f"Duplicates removed: {initial_count - len(df)}"
    )

    # Validate target labels.
    y = pd.to_numeric(
        df["class"],
        errors="coerce",
    )

    valid_target_rows = y.notna()

    df = df.loc[valid_target_rows].copy()
    y = y.loc[valid_target_rows].astype(int)

    target_classes = set(y.unique())

    if target_classes != {0, 1}:
        raise ValueError(
            "Binary dataset must contain both classes 0 and 1. "
            f"Found: {sorted(target_classes)}"
        )

    # Separate features and target.
    X = df.drop(columns=["class"]).copy()

    # Encode packer_type using a saved encoder.
    if "packer_type" not in X.columns:
        raise ValueError(
            "Expected 'packer_type' feature is missing."
        )

    X["packer_type"] = (
        X["packer_type"]
        .fillna("Unknown")
        .astype(str)
    )

    packer_encoder = LabelEncoder()

    X["packer_type"] = packer_encoder.fit_transform(
        X["packer_type"]
    )

    # Convert all features to numeric values and remove invalid rows.
    X = clean_numeric_features(
        X,
        "ClaMP binary dataset",
    )

    # Keep target rows aligned with the cleaned feature rows.
    y = y.loc[X.index]

    if len(X) != len(y):
        raise ValueError(
            "Feature and target row counts do not match."
        )

    feature_names = X.columns.tolist()

    if len(feature_names) != len(set(feature_names)):
        raise ValueError(
            "Duplicate feature names found in ClaMP dataset."
        )

    print(f"Usable records: {len(X)}")
    print(f"Total features: {len(feature_names)}")
    print(f"Feature names: {feature_names}")

    print(
        "Class distribution:",
        y.value_counts().sort_index().to_dict(),
    )

    # Stratified split.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples: {len(X_test)}"
    )

    # Fit scaler only on training data.
    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    # Validate processed arrays.
    if not np.isfinite(X_train_scaled).all():
        raise ValueError(
            "Non-finite values found in binary training features."
        )

    if not np.isfinite(X_test_scaled).all():
        raise ValueError(
            "Non-finite values found in binary test features."
        )

    # Save artifacts.
    save_artifacts(
        scaler=scaler,
        encoder=packer_encoder,
        feature_names=feature_names,
        scaler_filename="binary_scaler.joblib",
        encoder_filename="packer_encoder.joblib",
        feature_filename="binary_features.json",
    )

    save_processed_arrays(
        X_train_scaled,
        X_test_scaled,
        y_train.values,
        y_test.values,
        "binary",
    )

    print("\nBinary preprocessing completed.")
    print("Saved binary scaler, encoder and feature schema.")

    return (
        feature_names,
        X_train_scaled,
        X_test_scaled,
        y_train.values,
        y_test.values,
    )


def preprocess_multiclass():
    """
    Preprocess the DA-Proj dataset for malware-family classification.

    This dataset contains malware-family labels. It does not become
    a benign/malicious classifier by adding unused ClaMP records.
    """

    print("\n" + "=" * 60)
    print("PREPROCESSING MULTICLASS DATASET (Malware Families)")
    print("=" * 60)

    daproj_path = os.path.join(
        DATA_DIR,
        "daproj_headers.csv",
    )

    df = load_dataset(
        daproj_path,
        encoding="utf-8-sig",
    )

    required_columns = {
        "SHA256",
        "Malware_Type",
    }

    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            "DA-Proj dataset is missing required columns: "
            f"{sorted(missing_columns)}"
        )

    # Remove file identifiers and duplicate records.
    df = df.drop(
        columns=["SHA256"]
    ).drop_duplicates().copy()

    # Separate features and target.
    y_raw = df["Malware_Type"].astype(str).str.strip()

    valid_target_rows = (
        df["Malware_Type"].notna()
        & y_raw.ne("")
    )

    df = df.loc[valid_target_rows].copy()
    y_raw = y_raw.loc[valid_target_rows]

    X = df.drop(
        columns=["Malware_Type"]
    ).copy()

    # Convert features to numeric values.
    X = clean_numeric_features(
        X,
        "DA-Proj multiclass dataset",
    )

    # Keep target labels aligned with cleaned features.
    y_raw = y_raw.loc[X.index]

    if len(X) != len(y_raw):
        raise ValueError(
            "Multiclass feature and target row counts do not match."
        )

    # Encode malware-family labels.
    family_encoder = LabelEncoder()

    y = family_encoder.fit_transform(
        y_raw
    )

    if len(family_encoder.classes_) < 2:
        raise ValueError(
            "At least two malware-family classes are required."
        )

    class_counts = pd.Series(y).value_counts()

    if (class_counts < 2).any():
        raise ValueError(
            "Every malware family needs at least two records "
            "for a stratified train/test split."
        )

    multiclass_features = X.columns.tolist()

    if len(multiclass_features) != len(set(multiclass_features)):
        raise ValueError(
            "Duplicate feature names found in DA-Proj dataset."
        )

    print(f"Usable records: {len(X)}")
    print(f"Total features: {len(multiclass_features)}")

    print(
        "Malware families:",
        list(family_encoder.classes_),
    )

    print(
        "Family distribution:",
        y_raw.value_counts().to_dict(),
    )

    # Stratified train/test split.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    # Fit scaler on training data only.
    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    if not np.isfinite(X_train_scaled).all():
        raise ValueError(
            "Non-finite values found in multiclass training features."
        )

    if not np.isfinite(X_test_scaled).all():
        raise ValueError(
            "Non-finite values found in multiclass test features."
        )

    # Save preprocessing artifacts.
    save_artifacts(
        scaler=scaler,
        encoder=family_encoder,
        feature_names=multiclass_features,
        scaler_filename="multi_scaler.joblib",
        encoder_filename="family_encoder.joblib",
        feature_filename="multi_features.json",
    )

    save_processed_arrays(
        X_train_scaled,
        X_test_scaled,
        y_train,
        y_test,
        "multi",
    )

    print("\nMulticlass preprocessing completed.")
    print("Saved multiclass scaler, encoder and feature schema.")


if __name__ == "__main__":
    ensure_directories()

    preprocess_binary()
    preprocess_multiclass()

    print("\n" + "=" * 60)
    print("ALL PREPROCESSING TASKS COMPLETED")
    print("=" * 60)
