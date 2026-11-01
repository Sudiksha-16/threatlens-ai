import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


# Project directories
BASE_PATH = Path(__file__).resolve().parents[2]
ROOT_PATH = BASE_PATH.parent


class Settings(BaseSettings):

    PROJECT_NAME: str = "ThreatLens AI"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # Database
    MONGODB_URL: str = "mongodb uri"
    DATABASE_NAME: str = "threatlens_ai"

    # Security & JWT
    JWT_SECRET: str = (
        "${JWT_SECRET}"
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    # VirusTotal API
    VIRUSTOTAL_API_KEY: str = ""

    # Storage & Paths
    BASE_DIR: str = str(BASE_PATH)
    ROOT_DIR: str = str(ROOT_PATH)

    UPLOAD_DIR: str = str(BASE_PATH / "uploads")
    REPORTS_DIR: str = str(ROOT_PATH / "reports")

    YARA_RULES_PATH: str = str(
        ROOT_PATH / "yara_rules" / "malware_rules.yar"
    )

    # ML Models & Preprocessing
    ML_MODELS_DIR: str = str(
        BASE_PATH / "app" / "ml" / "saved_models"
    )

    PREPROCESSING_DIR: str = str(
        BASE_PATH / "app" / "ml" / "preprocessing"
    )

    EVALUATION_DIR: str = str(
        BASE_PATH / "app" / "ml" / "evaluation"
    )

    # Upload constraints
    MAX_FILE_SIZE_BYTES: int = 50 * 1024 * 1024

    model_config = SettingsConfigDict(
        env_file=str(ROOT_PATH / ".env"),
        env_file_encoding="utf-8",
        extra="allow",
    )


settings = Settings()


# Ensure required directories exist
required_directories = [
    settings.UPLOAD_DIR,
    settings.REPORTS_DIR,
    settings.ML_MODELS_DIR,
    settings.PREPROCESSING_DIR,
    settings.EVALUATION_DIR,
]

for path in required_directories:
    os.makedirs(path, exist_ok=True)