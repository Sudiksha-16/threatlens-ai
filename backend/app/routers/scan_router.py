import os
import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Query,
    status,
)

from backend.app.config.settings import settings
from backend.app.database.mongodb import get_database
from backend.app.models.scan import ScanDetailResponse
from backend.app.security.authentication import get_current_user
from backend.app.services.file_analyzer import perform_static_analysis
from backend.app.services.yara_engine import yara_engine
from backend.app.services.ml_engine import ml_engine
from backend.app.services.virustotal_service import virustotal_service
from backend.app.services.risk_engine import risk_engine


logger = logging.getLogger("threatlens.scan_router")

router = APIRouter(prefix="/scan", tags=["Scanning & Analysis"])


def get_user_id(current_user: dict):
    user_id = current_user.get(
        "user_id",
        current_user.get("_id")
    )

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable"
        )

    return user_id


@router.post("/upload", response_model=ScanDetailResponse)
async def upload_and_scan(
    file: UploadFile = File(...),
    scan_mode: str = Form("standard"),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable",
        )

    if scan_mode not in ("standard", "deep"):
        raise HTTPException(
            status_code=400,
            detail="Invalid scan mode. Use 'standard' or 'deep'.",
        )

    user_id = get_user_id(current_user)

    scan_id = str(uuid.uuid4())
    original_filename = file.filename or "uploaded_file"

    # Use a UUID-only filename for temporary storage.
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)

    temp_filename = f"{scan_id}.upload"
    temp_path = os.path.abspath(
        os.path.join(settings.UPLOAD_DIR, temp_filename)
    )

    # 1. Save uploaded file
    try:
        total_size = 0

        with open(temp_path, "wb") as buffer:
            while chunk := await file.read(65536):
                total_size += len(chunk)

                if total_size > settings.MAX_FILE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            "File exceeds maximum allowed limit of "
                            f"{settings.MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB"
                        ),
                    )

                buffer.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty (0 bytes)",
            )

    except HTTPException:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                logger.exception("Could not remove temporary upload.")
        raise

    except Exception:
        logger.exception("Error saving uploaded file")

        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                logger.exception("Could not remove temporary upload.")

        raise HTTPException(
            status_code=500,
            detail="Failed to process file upload",
        )

    created_at = datetime.now(timezone.utc)
    processing_errors = []

    try:
        # 2. Verify that the uploaded file is accessible
        try:
            if not os.path.isfile(temp_path):
                raise OSError("Uploaded file is no longer available.")

            with open(temp_path, "rb") as uploaded_file:
                uploaded_file.read(20)

        except OSError as e:
            logger.exception(
                "Uploaded file became inaccessible before scanning."
            )

            raise HTTPException(
                status_code=422,
                detail=(
                    "The uploaded file could not be accessed. "
                    "It may have been quarantined or blocked by "
                    "Windows Defender or another security tool."
                ),
            ) from e

        # 3. Static file analysis
        try:
            static_analysis = perform_static_analysis(
                temp_path,
                scan_mode=scan_mode,
            )

        except OSError as e:
            logger.exception(
                "Unable to read uploaded file during static analysis."
            )

            raise HTTPException(
                status_code=422,
                detail=(
                    "The uploaded file became inaccessible during scanning."
                ),
            ) from e

        # 4. YARA signature detection
        yara_matches = yara_engine.scan_file(temp_path)

        # 5. Initialize classification results
        ml_prediction = None
        vt_result = None

        classification = "Unclassified"
        malware_family = "Unknown"
        result_source = "No conclusive result"

        # 6. Run local ML only for PE files
        if static_analysis.get("is_pe") is True:
            logger.info(
                "Running PE malware model for %s",
                original_filename,
            )

            ml_prediction = ml_engine.predict(
                static_analysis,
                temp_path,
            )

        else:
            logger.info(
                "Skipping PE model for unsupported file type: %s",
                static_analysis.get("file_type"),
            )

            processing_errors.append(
                "The uploaded file is not a PE executable. "
                "The PE-trained ML model was not used."
            )

        # 7. Use a valid local ML prediction if available
        if (
            isinstance(ml_prediction, dict)
            and ml_prediction.get("classification") in [
                "Benign",
                "Malicious",
            ]
        ):
            classification = ml_prediction["classification"]

            malware_family = (
                ml_prediction.get("malware_family") or "Unknown"
            )

            result_source = "Local ML Classifier"

        else:
            if static_analysis.get("is_pe") is True:
                processing_errors.append(
                    "Local ML prediction was unavailable or invalid."
                )

            # 8. VirusTotal hash lookup fallback
            logger.info(
                "Using VirusTotal hash lookup for %s",
                original_filename,
            )

            result_source = "VirusTotal Threat Intelligence"

            vt_result = virustotal_service.query_file_hash(
                static_analysis["sha256"]
            )

            if (
                vt_result
                and vt_result.get("status") == "SUCCESS"
            ):
                positives = vt_result.get("positives", 0)

                if positives > 0:
                    classification = "Malicious"
                    malware_family = (
                        "Malicious Binary (VirusTotal Sourced)"
                    )

                else:
                    classification = "Unclassified"
                    malware_family = "Unknown"

                    processing_errors.append(
                        "VirusTotal returned no malicious or suspicious "
                        "detections. This does not establish that the "
                        "file is safe."
                    )

            else:
                classification = "Unclassified"
                malware_family = "Unknown"

                vt_status = (
                    vt_result.get("status", "UNKNOWN")
                    if vt_result
                    else "UNKNOWN"
                )

                processing_errors.append(
                    "VirusTotal could not provide a conclusive result. "
                    f"Status: {vt_status}"
                )

                result_source = "No conclusive result"

        # 9. Risk assessment
        risk_data = risk_engine.calculate_risk(
            static_analysis=static_analysis,
            yara_matches=yara_matches,
            ml_prediction=ml_prediction,
            vt_result=vt_result,
        )

        completed_at = datetime.now(timezone.utc)

        # 10. Model version
        if result_source == "Local ML Classifier":
            model_ver = ml_prediction.get(
                "model_version",
                "Unknown",
            )
        else:
            model_ver = "N/A"

        # 11. Save scan summary in MongoDB
        scan_doc = {
            "scan_id": scan_id,
            "user_id": user_id,
            "file_name": original_filename,
            "file_hash": static_analysis["sha256"],
            "file_size": static_analysis["file_size"],
            "file_type": static_analysis["file_type"],
            "scan_mode": scan_mode,
            "scan_status": "COMPLETED",
            "classification": classification,
            "malware_family": malware_family,
            "risk_score": risk_data["risk_score"],
            "risk_level": risk_data["risk_level"],
            "result_source": result_source,
            "model_version": model_ver,
            "created_at": created_at,
            "completed_at": completed_at,
        }

        await db.scans.insert_one(scan_doc)

        # 12. Save detailed scan results
        scan_results_doc = {
            "scan_id": scan_id,
            "user_id": user_id,
            "static_analysis": static_analysis,
            "yara_results": yara_matches,
            "ml_prediction": ml_prediction,
            "risk_assessment": risk_data,
            "virustotal": vt_result,
            "processing_errors": processing_errors,
            "created_at": created_at,
        }

        await db.scan_results.insert_one(scan_results_doc)

        # 13. Create alerts for High or Critical risk
        if risk_data["risk_level"] in ["Critical", "High"]:
            alert_id = str(uuid.uuid4())

            alert_title = (
                f"{risk_data['risk_level']} Threat Detected: "
                f"{original_filename}"
            )

            alert_desc = (
                f"File {original_filename} was classified as "
                f"{classification} with a Risk Score of "
                f"{risk_data['risk_score']}/100. "
                f"Key indicators: "
                f"{', '.join(risk_data['reasons'][:2])}."
            )

            alert_doc = {
                "alert_id": alert_id,
                "user_id": user_id,
                "scan_id": scan_id,
                "alert_type": (
                    "MALWARE_DETECTION"
                    if classification == "Malicious"
                    else "HIGH_RISK_ANOMALY"
                ),
                "severity": risk_data["risk_level"],
                "title": alert_title,
                "description": alert_desc,
                "file_name": original_filename,
                "file_hash": static_analysis["sha256"],
                "read_status": False,
                "resolution_status": False,
                "created_at": completed_at,
            }

            await db.alerts.insert_one(alert_doc)

        # 14. Audit log
        await db.audit_logs.insert_one({
            "user_id": user_id,
            "action": "FILE_SCANNED",
            "related_scan_id": scan_id,
            "timestamp": completed_at,
            "status": "SUCCESS",
        })

        # 15. Return complete scan response
        return {
            "scan_id": scan_id,
            "file_name": original_filename,
            "file_hash": static_analysis["sha256"],
            "file_size": static_analysis["file_size"],
            "file_type": static_analysis["file_type"],
            "scan_mode": scan_mode,
            "scan_status": "COMPLETED",
            "classification": classification,
            "malware_family": malware_family,
            "risk_score": risk_data["risk_score"],
            "risk_level": risk_data["risk_level"],
            "result_source": result_source,
            "model_version": model_ver,
            "created_at": created_at,
            "completed_at": completed_at,
            "static_analysis": static_analysis,
            "yara_results": yara_matches,
            "ml_prediction": ml_prediction,
            "risk_assessment": risk_data,
            "virustotal": vt_result,
            "processing_errors": processing_errors,
        }

    except HTTPException:
        raise

    except Exception:
        logger.exception("Scan processing failed")

        raise HTTPException(
            status_code=500,
            detail="An error occurred while analysing the uploaded file.",
        )

    finally:
        # 16. Secure cleanup of temporary uploaded file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                logger.exception(
                    "Could not remove temporary file: %s",
                    temp_path,
                )


@router.get("/history")
async def get_scan_history(
    search: Optional[str] = None,
    risk_level: Optional[str] = None,
    classification: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        )

    user_id = get_user_id(current_user)
    query = {"user_id": user_id}

    if risk_level and risk_level != "ALL":
        query["risk_level"] = risk_level

    if classification and classification != "ALL":
        query["classification"] = classification

    if search and search.strip():
        search_text = re.escape(search.strip())

        query["$or"] = [
            {
                "file_name": {
                    "$regex": search_text,
                    "$options": "i",
                }
            },
            {
                "file_hash": {
                    "$regex": search_text,
                    "$options": "i",
                }
            },
            {
                "scan_id": {
                    "$regex": search_text,
                    "$options": "i",
                }
            },
        ]

    total = await db.scans.count_documents(query)

    cursor = (
        db.scans.find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    scans = await cursor.to_list(length=limit)

    for scan in scans:
        scan["_id"] = str(scan["_id"])

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "scans": scans,
    }


@router.get("/simulate/{scenario}")
async def simulate_scan(
    scenario: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Generate simulated scan results for demonstration purposes.

    These results are not real malware scans and are not saved
    to MongoDB, scan history, alerts, or dashboard statistics.
    """

    scenario = scenario.lower().strip()

    scenarios = {
        "clean": {
            "file_name": "clean_sample.exe",
            "classification": "Benign",
            "malware_family": "None Detected",
            "entropy": 5.2,
            "obfuscation_indicators": [],
            "imported_apis": [],
            "suspicious_strings": [],
            "yara_results": [],
            "ml_probability": 0.01,
        },

        "suspicious": {
            "file_name": "suspicious_sample.exe",
            "classification": "Benign",
            "malware_family": "Suspicious Indicators",
            "entropy": 7.5,
            "obfuscation_indicators": ["Possible code obfuscation"],
            "imported_apis": [
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
            "suspicious_strings": [
                "powershell.exe",
                "cmd.exe",
            ],
            "yara_results": [
                {
                    "rule_name": "Suspicious_Execution_Pattern",
                    "category": "Suspicious Activity",
                    "severity": "Medium",
                    "description": "Simulated suspicious execution indicators.",
                }
            ],
            "ml_probability": 0.10,
        },

        "malicious": {
            "file_name": "malicious_sample.exe",
            "classification": "Malicious",
            "malware_family": "Trojan",
            "entropy": 7.6,
            "obfuscation_indicators": [
                "Code packing detected",
                "Possible API obfuscation",
            ],
            "imported_apis": [
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "WinExec",
            ],
            "suspicious_strings": [
                "powershell.exe",
                "cmd.exe",
                "download",
            ],
            "yara_results": [
                {
                    "rule_name": "Trojan_Downloader_Detection",
                    "category": "Trojan",
                    "severity": "High",
                    "description": "Simulated Trojan downloader indicators.",
                }
            ],
            "ml_probability": 0.85,
        },

        "critical": {
            "file_name": "critical_threat_sample.exe",
            "classification": "Malicious",
            "malware_family": "Ransomware",
            "entropy": 7.9,
            "obfuscation_indicators": [
                "Heavy code packing",
                "Multiple obfuscation indicators",
            ],
            "imported_apis": [
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "CryptEncrypt",
                "DeleteFile",
            ],
            "suspicious_strings": [
                "vssadmin delete shadows",
                "ransom_note",
                "encrypted_files",
                "bitcoin",
            ],
            "yara_results": [
                {
                    "rule_name": "Critical_Ransomware_Behavior",
                    "category": "Ransomware",
                    "severity": "Critical",
                    "description": "Simulated ransomware behavior and file encryption indicators.",
                }
            ],
            "ml_probability": 0.99,
        },

        "unknown": {
            "file_name": "unknown_sample.bin",
            "classification": "Unclassified",
            "malware_family": "Unknown",
            "entropy": 0,
            "obfuscation_indicators": [],
            "imported_apis": [],
            "suspicious_strings": [],
            "yara_results": [],
            "ml_probability": None,
        },
    }

    if scenario not in scenarios:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid scenario. Choose clean, suspicious, "
                "malicious, critical, or unknown."
            ),
        )

    sample = scenarios[scenario]

    # Synthetic static analysis data.
    static_analysis = {
        "file_type": (
            "PE Executable"
            if scenario != "unknown"
            else "Unknown Binary"
        ),
        "file_size": 1024 * 250,
        "entropy": sample["entropy"],
        "is_pe": scenario != "unknown",
        "sha256": "SIMULATED-NOT-A-REAL-HASH",
        "md5": "SIMULATED-NOT-A-REAL-HASH",
        "sections": [],
        "imported_apis": sample["imported_apis"],
        "suspicious_strings": sample["suspicious_strings"],
        "obfuscation_indicators": sample["obfuscation_indicators"],
    }

    yara_matches = sample["yara_results"]

    # Synthetic ML prediction.
    ml_prediction = None

    if sample["ml_probability"] is not None:
        probability = sample["ml_probability"]

        ml_prediction = {
            "classification": sample["classification"],
            "malware_family": sample["malware_family"],
            "model_name": "Random Forest",
            "model_version": "SIMULATED",
            "confidence": (
                probability
                if sample["classification"] == "Malicious"
                else 1 - probability
            ),
            "class_probabilities": {
                "Malicious": probability,
                "Benign": 1 - probability,
            },
        }

    # Use the actual ThreatLens risk engine.
    risk_data = risk_engine.calculate_risk(
        static_analysis=static_analysis,
        yara_matches=yara_matches,
        ml_prediction=ml_prediction,
        vt_result=None,
    )

    now = datetime.now(timezone.utc)

    return {
        "scan_id": f"SIMULATED-{scenario.upper()}",
        "file_name": sample["file_name"],
        "file_hash": "SIMULATED-NOT-A-REAL-HASH",
        "file_size": static_analysis["file_size"],
        "file_type": static_analysis["file_type"],
        "scan_mode": "simulation",
        "scan_status": "COMPLETED",
        "classification": sample["classification"],
        "malware_family": sample["malware_family"],
        "risk_score": risk_data["risk_score"],
        "risk_level": risk_data["risk_level"],
        "result_source": "Simulated Demonstration",
        "model_version": "SIMULATED",
        "created_at": now,
        "completed_at": now,
        "static_analysis": static_analysis,
        "yara_results": yara_matches,
        "ml_prediction": ml_prediction,
        "risk_assessment": risk_data,
        "virustotal": None,
        "processing_errors": [],
        "is_simulated": True,
        "simulation_notice": (
            "SIMULATED — NOT A REAL MALWARE SCAN. "
            "All file attributes and detection results are synthetic."
        ),
    }

@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_detail(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        )

    user_id = get_user_id(current_user)

    scan = await db.scans.find_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan record not found or unauthorized",
        )

    scan_result = await db.scan_results.find_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    if not scan_result:
        raise HTTPException(
            status_code=404,
            detail="Scan result details not found",
        )

    return {
        "scan_id": scan["scan_id"],
        "file_name": scan["file_name"],
        "file_hash": scan["file_hash"],
        "file_size": scan["file_size"],
        "file_type": scan["file_type"],
        "scan_mode": scan.get("scan_mode", "standard"),
        "scan_status": scan.get("scan_status", "COMPLETED"),
        "classification": scan["classification"],
        "malware_family": scan.get("malware_family"),
        "risk_score": scan["risk_score"],
        "risk_level": scan["risk_level"],
        "result_source": scan.get(
            "result_source",
            "No conclusive result",
        ),
        "model_version": scan.get("model_version", "N/A"),
        "created_at": scan["created_at"],
        "completed_at": scan.get("completed_at"),
        "static_analysis": scan_result.get("static_analysis", {}),
        "yara_results": scan_result.get("yara_results", []),
        "ml_prediction": scan_result.get("ml_prediction"),
        "risk_assessment": scan_result.get("risk_assessment", {}),
        "virustotal": scan_result.get("virustotal"),
        "processing_errors": scan_result.get("processing_errors"),
    }


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        )

    user_id = get_user_id(current_user)

    result = await db.scans.delete_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    if result.deleted_count == 0:
        raise HTTPException(
            status_code=404,
            detail="Scan record not found",
        )

    await db.scan_results.delete_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    await db.alerts.delete_many({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    return {
        "message": "Scan record and associated results deleted successfully"
    }
