

import os
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials

from backend.app.config.settings import settings
from backend.app.database.mongodb import get_database
from backend.app.security.authentication import (
    get_current_user,
    get_current_user_from_token_str,
    security_bearer,
)
from backend.app.services.report_generator import generate_pdf_report


logger = logging.getLogger("threatlens.reports_router")

router = APIRouter(
    prefix="/reports",
    tags=["PDF Reports"],
)


def get_user_id(current_user: dict):
    """Extract the authenticated user's ID."""

    user_id = current_user.get(
        "user_id",
        current_user.get("_id"),
    )

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable",
        )

    return user_id


def create_report_filename(scan: dict, scan_id: str) -> str:
    """Create a safe PDF filename from the uploaded file name."""

    original_name = os.path.basename(
        str(scan.get("file_name") or "binary")
    )

    clean_name = "".join(
        character
        for character in original_name
        if character.isalnum() or character in "._- "
    ).strip()

    clean_name = clean_name[:100] or "binary"

    if clean_name.lower().endswith(".pdf"):
        clean_name = clean_name[:-4]

    return (
        f"ThreatLens_Report_{scan_id[:8]}_"
        f"{clean_name}.pdf"
    )


def get_report_path(filename: str) -> str:
    """Build and validate a path inside the reports directory."""

    reports_dir = os.path.realpath(
        settings.REPORTS_DIR
    )

    os.makedirs(
        reports_dir,
        exist_ok=True,
    )

    file_path = os.path.realpath(
        os.path.join(reports_dir, filename)
    )

    if os.path.commonpath(
        [reports_dir, file_path]
    ) != reports_dir:
        raise HTTPException(
            status_code=400,
            detail="Invalid report file path",
        )

    return file_path


async def generate_and_save_report(
    scan: dict,
    scan_result: dict,
    scan_id: str,
    user_id,
) -> dict:
    """Generate a PDF and save its database record."""

    filename = create_report_filename(
        scan,
        scan_id,
    )

    output_path = get_report_path(filename)

    try:
        generate_pdf_report(
            scan,
            scan_result,
            output_path,
        )

        if not os.path.isfile(output_path):
            raise RuntimeError(
                "PDF generation did not produce an output file."
            )

        report_doc = {
            "user_id": user_id,
            "scan_id": scan_id,
            "report_type": "PDF_AUDIT_REPORT",
            "report_location": output_path,
            "filename": filename,
            "generated_at": datetime.now(timezone.utc),
        }

        return report_doc

    except Exception:
        logger.exception(
            "Failed to generate report for scan %s",
            scan_id,
        )

        raise


@router.post("/generate/{scan_id}")
async def create_report(
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
            detail="Scan record not found",
        )

    scan_result = await db.scan_results.find_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    if not scan_result:
        raise HTTPException(
            status_code=404,
            detail="Scan result not found",
        )

    try:
        report_doc = await generate_and_save_report(
            scan,
            scan_result,
            scan_id,
            user_id,
        )

        await db.reports.update_one(
            {
                "scan_id": scan_id,
                "user_id": user_id,
            },
            {
                "$set": report_doc,
            },
            upsert=True,
        )

        return {
            "message": "Report generated successfully",
            "download_url": f"/api/reports/download/{scan_id}",
            "filename": report_doc["filename"],
        }

    except Exception:
        logger.exception(
            "Report generation failed for scan %s",
            scan_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to generate PDF report",
        )


@router.get("/download/{scan_id}")
async def download_report(
    scan_id: str,
    token: Optional[str] = Query(None),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        security_bearer
    ),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        )

    # Authenticate using the authorization header or query token.
    auth_token = (
        credentials.credentials
        if credentials
        else token
    )

    if not auth_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication token required",
        )

    try:
        current_user = await get_current_user_from_token_str(
            auth_token
        )

        user_id = get_user_id(current_user)

    except HTTPException:
        raise

    except Exception:
        logger.warning(
            "Report download authentication failed."
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token",
        )

    # Verify scan ownership.
    scan = await db.scans.find_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found or unauthorized",
        )

    # Retrieve the user's report.
    report_record = await db.reports.find_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    # Generate the report if it does not already exist.
    if not report_record:
        report_record = None

    if report_record:
        stored_path = report_record.get(
            "report_location",
            "",
        )

        filename = report_record.get(
            "filename",
            "",
        )

        # Never trust a stored path without validating it.
        if not filename:
            filename = create_report_filename(
                scan,
                scan_id,
            )

        file_path = get_report_path(
            os.path.basename(filename)
        )

        # Reuse the stored report if it exists inside the reports directory.
        if (
            os.path.isfile(file_path)
            and stored_path
            and os.path.realpath(stored_path) == file_path
        ):
            return FileResponse(
                path=file_path,
                filename=os.path.basename(filename),
                media_type="application/pdf",
            )

    # Generate a new report when missing or unavailable.
    scan_result = await db.scan_results.find_one({
        "scan_id": scan_id,
        "user_id": user_id,
    })

    if not scan_result:
        raise HTTPException(
            status_code=404,
            detail="Scan result not found",
        )

    try:
        report_doc = await generate_and_save_report(
            scan,
            scan_result,
            scan_id,
            user_id,
        )

        await db.reports.update_one(
            {
                "scan_id": scan_id,
                "user_id": user_id,
            },
            {
                "$set": report_doc,
            },
            upsert=True,
        )

        return FileResponse(
            path=report_doc["report_location"],
            filename=report_doc["filename"],
            media_type="application/pdf",
        )

    except Exception:
        logger.exception(
            "Could not prepare report download for scan %s",
            scan_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to generate or download report",
        )
