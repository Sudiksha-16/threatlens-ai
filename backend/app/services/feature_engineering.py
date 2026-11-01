import os
import json
import logging
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib

from backend.app.config.settings import settings

logger = logging.getLogger("threatlens.feature_engineering")


class FeatureEngineer:

    def __init__(self):
        self.scaler = None
        self.packer_encoder = None
        self.feature_names = []
        self.artifacts_loaded = False

        self._load_artifacts()

    def _load_artifacts(self):
        try:
            scaler_path = os.path.join(
                settings.PREPROCESSING_DIR,
                "binary_scaler.joblib",
            )

            encoder_path = os.path.join(
                settings.PREPROCESSING_DIR,
                "packer_encoder.joblib",
            )

            features_path = os.path.join(
                settings.PREPROCESSING_DIR,
                "binary_features.json",
            )

            required_files = [
                scaler_path,
                encoder_path,
                features_path,
            ]

            missing_files = [
                path for path in required_files
                if not os.path.exists(path)
            ]

            if missing_files:
                raise FileNotFoundError(
                    f"Missing preprocessing artifacts: {missing_files}"
                )

            self.scaler = joblib.load(scaler_path)
            self.packer_encoder = joblib.load(encoder_path)

            with open(features_path, "r", encoding="utf-8") as f:
                self.feature_names = json.load(f)

            if not isinstance(self.feature_names, list):
                raise ValueError("Feature names must be a list.")

            if len(self.feature_names) != 69:
                raise ValueError(
                    f"Expected 69 binary features, "
                    f"found {len(self.feature_names)}."
                )

            if len(set(self.feature_names)) != len(self.feature_names):
                raise ValueError("Duplicate feature names detected.")

            if not hasattr(self.scaler, "n_features_in_"):
                raise ValueError(
                    "Loaded scaler does not expose its feature count."
                )

            if self.scaler.n_features_in_ != len(self.feature_names):
                raise ValueError(
                    "Scaler feature count does not match feature list."
                )

            if self.packer_encoder is None or not hasattr(
                self.packer_encoder, "classes_"
            ):
                raise ValueError("Packer encoder is invalid.")

            logger.info(
                "Feature engineering artifacts loaded successfully. "
                "Features: %s",
                len(self.feature_names),
            )

            logger.info(
                "Packer encoder classes: %s",
                list(self.packer_encoder.classes_),
            )

            self.artifacts_loaded = True

        except Exception as e:
            logger.exception(
                "Could not load feature engineering artifacts: %s",
                e,
            )
            self.artifacts_loaded = False

    def _get_no_packer_encoding(self):
        """
        Find an explicitly identifiable no-packer category.
        Do not assume that encoded value 0 means NoPacker.
        """

        if self.packer_encoder is None:
            raise ValueError("Packer encoder is unavailable.")

        classes = list(self.packer_encoder.classes_)

        no_packer_labels = {
            "none",
            "nopacker",
            "no_packer",
            "no packer",
            "not packed",
            "unpacked",
        }

        for index, label in enumerate(classes):
            normalized = str(label).strip().lower()

            if normalized in no_packer_labels:
                return float(index)

        raise ValueError(
            "Could not identify the NoPacker category in the saved "
            f"encoder. Available classes: {classes}"
        )

    def extract_feature_vector(
        self,
        static_info: dict,
        file_path: str = None,
    ) -> np.ndarray:

        if not self.artifacts_loaded:
            raise RuntimeError(
                "Feature engineering artifacts are not loaded."
            )

        if not isinstance(static_info, dict):
            raise ValueError("Static analysis information is invalid.")

        if static_info.get("is_pe") is not True:
            raise ValueError(
                "The binary PE model only supports PE executable files."
            )

        if not file_path or not os.path.isfile(file_path):
            raise FileNotFoundError(
                "Valid PE file path is required for feature extraction."
            )

        import pefile

        features_dict = {
            feature: 0.0
            for feature in self.feature_names
        }

        # Basic file information
        features_dict["filesize"] = float(
            static_info.get("file_size", 0)
        )

        features_dict["E_file"] = float(
            static_info.get("entropy", 0.0)
        )

        pe = None

        try:
            pe = pefile.PE(file_path, fast_load=True)

            # DOS Header
            if hasattr(pe, "DOS_HEADER"):
                dos = pe.DOS_HEADER

                for name in [
                    "e_cblp",
                    "e_cp",
                    "e_cparhdr",
                    "e_maxalloc",
                    "e_sp",
                    "e_lfanew",
                ]:
                    features_dict[name] = float(
                        getattr(dos, name, 0)
                    )

            else:
                raise ValueError("PE DOS header is missing.")

            # File Header
            if hasattr(pe, "FILE_HEADER"):
                header = pe.FILE_HEADER

                features_dict["NumberOfSections"] = float(
                    getattr(header, "NumberOfSections", 0)
                )

                timestamp = getattr(
                    header,
                    "TimeDateStamp",
                    0,
                )

                # Match the original ClaMP CreationYear definition.
                # 1.0 for years 1980-2015 inclusive; otherwise 0.0.
                try:
                    creation_year = datetime.fromtimestamp(
                        timestamp,
                        tz=timezone.utc,
                    ).year

                    features_dict["CreationYear"] = float(
                        1980 <= creation_year <= 2015
                    )

                except (ValueError, OSError, OverflowError):
                    raise ValueError("Invalid PE timestamp.")

                characteristics = getattr(
                    header,
                    "Characteristics",
                    0,
                )

                for i in range(15):
                    features_dict[f"FH_char{i}"] = float(
                        bool(characteristics & (1 << i))
                    )

            else:
                raise ValueError("PE file header is missing.")

            # Optional Header
            if hasattr(pe, "OPTIONAL_HEADER"):
                opt = pe.OPTIONAL_HEADER

                optional_fields = [
                    "MajorLinkerVersion",
                    "MinorLinkerVersion",
                    "SizeOfCode",
                    "SizeOfInitializedData",
                    "SizeOfUninitializedData",
                    "AddressOfEntryPoint",
                    "BaseOfCode",
                    "BaseOfData",
                    "ImageBase",
                    "SectionAlignment",
                    "FileAlignment",
                    "MajorOperatingSystemVersion",
                    "MinorOperatingSystemVersion",
                    "MajorImageVersion",
                    "MinorImageVersion",
                    "MajorSubsystemVersion",
                    "MinorSubsystemVersion",
                    "SizeOfImage",
                    "SizeOfHeaders",
                    "CheckSum",
                    "Subsystem",
                ]

                for name in optional_fields:
                    if name in features_dict:
                        features_dict[name] = float(
                            getattr(opt, name, 0)
                        )

                dll_chars = getattr(
                    opt,
                    "DllCharacteristics",
                    0,
                )

                for i in range(11):
                    features_dict[f"OH_DLLchar{i}"] = float(
                        bool(dll_chars & (1 << i))
                    )

                for name in [
                    "SizeOfStackReserve",
                    "SizeOfStackCommit",
                    "SizeOfHeapReserve",
                    "SizeOfHeapCommit",
                    "LoaderFlags",
                ]:
                    features_dict[name] = float(
                        getattr(opt, name, 0)
                    )

            else:
                raise ValueError("PE optional header is missing.")

            # Section information
            suspicious_sections = 0
            normal_sections = 0

            text_entropy = 0.0
            data_entropy = 0.0

            for section in pe.sections:

                section_name = (
                    section.Name.decode(
                        "utf-8",
                        errors="ignore",
                    )
                    .strip("\x00")
                    .lower()
                )

                section_entropy = float(
                    section.get_entropy()
                )

                if ".text" in section_name:
                    text_entropy = section_entropy

                elif ".data" in section_name:
                    data_entropy = section_entropy

                suspicious_name = any(
                    packer in section_name
                    for packer in [
                        "upx",
                        "aspack",
                        "fsg",
                        "mew",
                        "mpress",
                        "themida",
                    ]
                )

                if suspicious_name or section_entropy > 7.2:
                    suspicious_sections += 1
                else:
                    normal_sections += 1

            features_dict["sus_sections"] = float(
                suspicious_sections
            )

            features_dict["non_sus_sections"] = float(
                normal_sections
            )

            features_dict["E_text"] = float(text_entropy)
            features_dict["E_data"] = float(data_entropy)

            # Basic packed indicator
            is_packed = (
                suspicious_sections > 0
                or features_dict["E_file"] > 7.2
            )

            features_dict["packer"] = float(is_packed)

            # File information indicator
            features_dict["fileinfo"] = float(
                hasattr(pe, "VS_VERSIONINFO")
            )

            # Packer category
            if is_packed:
                raise ValueError(
                    "Packed file detected, but the exact packer_type "
                    "cannot be reliably identified by this extractor."
                )

            features_dict["packer_type"] = (
                self._get_no_packer_encoding()
            )

        except Exception as e:
            logger.error(
                "PE feature extraction failed: %s",
                e,
            )
            raise

        finally:
            if pe is not None:
                pe.close()

        # Validate extracted values
        raw_values = [
            features_dict[name]
            for name in self.feature_names
        ]

        raw_vector = np.asarray(
            [raw_values],
            dtype=np.float64,
        )

        if raw_vector.shape != (1, len(self.feature_names)):
            raise ValueError(
                f"Invalid feature vector shape: {raw_vector.shape}"
            )

        if not np.isfinite(raw_vector).all():
            raise ValueError(
                "Feature vector contains NaN or infinite values."
            )

        # Preserve the original feature names and order for the scaler.
        raw_df = pd.DataFrame(
            raw_vector,
            columns=self.feature_names,
        )

        # Apply the same scaler used during training.
        scaled_vector = self.scaler.transform(raw_df)

        if scaled_vector.shape != raw_vector.shape:
            raise ValueError(
                "Scaled feature vector shape mismatch."
            )

        return scaled_vector


feature_engineer = FeatureEngineer()
