

import os
import json
import logging

from fastapi import APIRouter, Depends, HTTPException

from backend.app.config.settings import settings
from backend.app.database.mongodb import get_database
from backend.app.security.authentication import get_current_user


logger = logging.getLogger("threatlens.model_router")

router = APIRouter(
    prefix="/model",
    tags=["Model Performance"],
)


def load_json_file(file_path: str, default):
    """Safely load a JSON file."""

    if not os.path.isfile(file_path):
        logger.warning("File not found: %s", file_path)
        return default

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        logger.exception(
            "Could not read JSON file: %s",
            file_path,
        )
        return default


@router.get("/performance")
async def get_model_performance(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    """Return model performance, evaluation and feature information."""

    meta_path = os.path.join(
        settings.ML_MODELS_DIR,
        "model_metadata.json",
    )

    detailed_eval_path = os.path.join(
        settings.ROOT_DIR,
        "training",
        "models",
        "detailed_evaluation.json",
    )

    features_path = os.path.join(
        settings.PREPROCESSING_DIR,
        "binary_features.json",
    )

    # Load local model information.
    metadata = load_json_file(meta_path, {})
    detailed_eval = load_json_file(detailed_eval_path, {})
    features = load_json_file(features_path, [])

    # Validate loaded JSON structures.
    if not isinstance(metadata, dict):
        metadata = {}

    if not isinstance(detailed_eval, dict):
        detailed_eval = {}

    if not isinstance(features, list):
        features = []

    # Active model information.
    active_name = metadata.get("active_model") or "Unavailable"

    if not isinstance(active_name, str):
        active_name = "Unavailable"

    models_comparison = metadata.get("models_comparison") or {}

    if not isinstance(models_comparison, dict):
        models_comparison = {}

    active_metrics = models_comparison.get(active_name, {})

    if not isinstance(active_metrics, dict):
        active_metrics = {}

    # Check whether the active model file exists.
    active_model_file = metadata.get(
        "active_model_file",
        "active_binary_model.joblib",
    )

    model_available = False

    if isinstance(active_model_file, str) and active_model_file:
        model_path = os.path.join(
            settings.ML_MODELS_DIR,
            os.path.basename(active_model_file),
        )

        model_available = os.path.isfile(model_path)

    # Retrieve model registry information from MongoDB.
    db_models = []

    if db is not None:
        try:
            cursor = (
                db.model_registry
                .find({})
                .sort("active_status", -1)
            )

            db_models = await cursor.to_list(length=20)

            for model in db_models:
                model["_id"] = str(model["_id"])

        except Exception:
            logger.exception(
                "Could not retrieve model registry from MongoDB."
            )

    # Build response.
    return {
        "active_model": {
            "name": active_name.replace("_", " "),
            "version": metadata.get("version", "N/A"),
            "dataset_name": metadata.get(
                "dataset_name",
                "N/A",
            ),
            "training_records": metadata.get(
                "training_records",
                0,
            ),
            "num_features": metadata.get(
                "num_features",
                len(features),
            ),
            "training_date": metadata.get(
                "training_date",
                "N/A",
            ),
            "status": (
                "Active & In Service"
                if model_available
                else "Unavailable"
            ),
            "metrics": active_metrics,
        },
        "all_models_comparison": models_comparison,
        "detailed_evaluation": detailed_eval,
        "multiclass_metrics": metadata.get(
            "multiclass_metrics",
            {},
        ),
        "features": features,
        "database_registry": db_models,
    }
