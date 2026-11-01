
import os
import json
import logging
from typing import Dict, Any, Optional

import joblib
import numpy as np

from backend.app.config.settings import settings
from backend.app.services.feature_engineering import feature_engineer

logger = logging.getLogger("threatlens.ml_engine")


class MLEngine:

    def __init__(self):
        self.active_model = None
        self.multiclass_model = None
        self.family_encoder = None
        self.model_metadata = {}
        self.is_loaded = False

        self.load_models()

    def load_models(self):
        try:
            active_path = os.path.join(
                settings.ML_MODELS_DIR,
                "active_binary_model.joblib",
            )

            multi_path = os.path.join(
                settings.ML_MODELS_DIR,
                "multiclass_family_model.joblib",
            )

            encoder_path = os.path.join(
                settings.PREPROCESSING_DIR,
                "family_encoder.joblib",
            )

            meta_path = os.path.join(
                settings.ML_MODELS_DIR,
                "model_metadata.json",
            )

            # Load binary classification model
            if not os.path.exists(active_path):
                raise FileNotFoundError(
                    f"Binary model not found: {active_path}"
                )

            self.active_model = joblib.load(active_path)

            # Load multiclass artifacts for future family prediction.
            # They are NOT used until a separate 53-feature extractor
            # has been implemented and validated.
            if os.path.exists(multi_path):
                self.multiclass_model = joblib.load(multi_path)

            if os.path.exists(encoder_path):
                self.family_encoder = joblib.load(encoder_path)

            # Load model metadata
            if os.path.exists(meta_path):
                with open(
                    meta_path,
                    "r",
                    encoding="utf-8",
                ) as f:
                    self.model_metadata = json.load(f)

            # Validate binary model
            if not hasattr(self.active_model, "classes_"):
                raise ValueError(
                    "Binary model does not expose classes_."
                )

            model_classes = list(self.active_model.classes_)

            if set(model_classes) != {0, 1}:
                raise ValueError(
                    f"Unexpected binary model classes: {model_classes}. "
                    "Expected 0 = Benign and 1 = Malicious."
                )

            if not hasattr(self.active_model, "n_features_in_"):
                raise ValueError(
                    "Binary model does not expose n_features_in_."
                )

            expected_features = self.active_model.n_features_in_

            if not feature_engineer.artifacts_loaded:
                raise RuntimeError(
                    "Feature engineering artifacts are unavailable."
                )

            if expected_features != len(
                feature_engineer.feature_names
            ):
                raise ValueError(
                    "Binary model and feature extractor have different "
                    f"feature counts. Model: {expected_features}, "
                    f"Extractor: {len(feature_engineer.feature_names)}."
                )

            # This implementation requires probability estimates.
            if not hasattr(self.active_model, "predict_proba"):
                raise ValueError(
                    "Binary model must support predict_proba()."
                )

            self.is_loaded = True

            logger.info(
                "Binary ML model loaded successfully. "
                "Model: %s, Features: %s, Classes: %s",
                self.model_metadata.get(
                    "active_model",
                    "Unknown",
                ),
                expected_features,
                model_classes,
            )

        except Exception as e:
            logger.exception(
                "Failed to load ML models: %s",
                e,
            )

            self.active_model = None
            self.is_loaded = False

    def predict(
        self,
        static_info: dict,
        file_path: str = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Performs binary PE malware classification.

        Returns None when:
        - Model is unavailable.
        - File is not a supported PE executable.
        - Feature extraction fails.
        - Model input validation fails.
        - Prediction cannot be completed reliably.
        """

        if not self.is_loaded or self.active_model is None:
            logger.warning(
                "Prediction requested but binary model is unavailable."
            )
            return None

        try:
            # Only PE files are supported by this trained model.
            if static_info.get("is_pe") is not True:
                logger.warning(
                    "Skipping ML prediction: unsupported non-PE file."
                )
                return None

            # Extract the same features used during training.
            feature_vector = (
                feature_engineer.extract_feature_vector(
                    static_info,
                    file_path,
                )
            )

            # Validate feature vector
            if not isinstance(feature_vector, np.ndarray):
                raise ValueError(
                    "Feature extractor did not return a NumPy array."
                )

            if feature_vector.ndim != 2:
                raise ValueError(
                    f"Expected a 2D feature vector, "
                    f"received shape {feature_vector.shape}."
                )

            expected_features = self.active_model.n_features_in_

            if feature_vector.shape != (1, expected_features):
                raise ValueError(
                    f"Feature count mismatch. Expected "
                    f"{expected_features}, got {feature_vector.shape}."
                )

            if not np.isfinite(feature_vector).all():
                raise ValueError(
                    "Feature vector contains invalid numeric values."
                )

            # Binary prediction
            prediction = self.active_model.predict(
                feature_vector
            )[0]

            prediction = int(prediction)

            if prediction not in [0, 1]:
                raise ValueError(
                    f"Unexpected predicted class: {prediction}"
                )

            is_malicious = prediction == 1

            # Probability prediction
            probabilities = (
                self.active_model.predict_proba(
                    feature_vector
                )[0]
            )

            # Read actual class ordering from the trained model.
            model_classes = list(self.active_model.classes_)

            benign_index = model_classes.index(0)
            malicious_index = model_classes.index(1)

            p_benign = float(
                probabilities[benign_index]
            )

            p_malicious = float(
                probabilities[malicious_index]
            )

            # Validate probability values
            if not (
                np.isfinite(p_benign)
                and np.isfinite(p_malicious)
            ):
                raise ValueError(
                    "Model returned invalid probabilities."
                )

            if not np.isclose(
                p_benign + p_malicious,
                1.0,
                atol=1e-5,
            ):
                raise ValueError(
                    "Model probabilities do not sum to 1."
                )

            confidence = (
                p_malicious if is_malicious else p_benign
            )

            # Multiclass family prediction is intentionally disabled.
            # The binary model has 69 features, while the family model
            # requires a separate 53-feature extraction pipeline.
            if is_malicious:
                malware_family = "Unknown"
            else:
                malware_family = "Benign Software"

            result = {
                "classification": (
                    "Malicious" if is_malicious else "Benign"
                ),
                "is_malicious": is_malicious,
                "confidence": round(confidence, 4),
                "class_probabilities": {
                    "Benign": round(p_benign, 4),
                    "Malicious": round(p_malicious, 4),
                },
                "malware_family": malware_family,
                "model_name": self.model_metadata.get(
                    "active_model",
                    "Random_Forest",
                ),
                "model_version": self.model_metadata.get(
                    "version",
                    "1.0.0",
                ),
            }

            logger.info(
                "ML prediction completed: %s "
                "(Benign: %.4f, Malicious: %.4f)",
                result["classification"],
                p_benign,
                p_malicious,
            )

            return result

        except Exception as e:
            logger.exception(
                "Error during ML inference: %s",
                e,
            )

            return None


ml_engine = MLEngine()
