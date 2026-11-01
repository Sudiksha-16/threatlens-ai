
import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.database.mongodb import get_database
from backend.app.models.user import (
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    UserUpdateSettings,
)
from backend.app.security.password import (
    hash_password,
    verify_password,
    validate_password_strength,
)
from backend.app.security.authentication import (
    create_access_token,
    get_current_user,
)


logger = logging.getLogger("threatlens.auth_router")

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def get_user_id(current_user: dict):
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


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user_data: UserRegister,
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable",
        )

    email = user_data.email.strip().lower()
    full_name = user_data.full_name.strip()

    if not full_name:
        raise HTTPException(
            status_code=400,
            detail="Full name cannot be empty",
        )

    if user_data.password != user_data.confirm_password:
        raise HTTPException(
            status_code=400,
            detail="Passwords do not match",
        )

    is_valid, msg = validate_password_strength(
        user_data.password
    )

    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=msg,
        )

    # Check whether the email already exists
    existing_user = await db.users.find_one({
        "email": email
    })

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email address already exists",
        )

    user_id = str(uuid.uuid4())
    password_hash = hash_password(user_data.password)
    created_at = datetime.now(timezone.utc)

    user_doc = {
        "user_id": user_id,
        "full_name": full_name,
        "email": email,
        "password_hash": password_hash,
        "role": "analyst",
        "account_status": "active",
        "created_at": created_at,
        "notification_preferences": {
            "alerts": True,
            "reports": True,
        },
        "scan_retention_days": 90,
    }

    await db.users.insert_one(user_doc)

    # Audit log
    await db.audit_logs.insert_one({
        "user_id": user_id,
        "action": "USER_REGISTERED",
        "timestamp": created_at,
        "status": "SUCCESS",
    })

    # Generate access token
    token = create_access_token({
        "sub": email,
        "user_id": user_id,
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "full_name": full_name,
            "email": email,
            "role": user_doc["role"],
            "created_at": created_at,
            "account_status": user_doc["account_status"],
            "notification_preferences": (
                user_doc["notification_preferences"]
            ),
        },
    }


@router.post(
    "/login",
    response_model=TokenResponse,
)
async def login(
    credentials: UserLogin,
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable",
        )

    email = credentials.email.strip().lower()

    user = await db.users.find_one({
        "email": email
    })

    if (
        not user
        or not verify_password(
            credentials.password,
            user.get("password_hash", ""),
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if user.get("account_status") == "suspended":
        raise HTTPException(
            status_code=403,
            detail="Account is suspended. Contact administrator.",
        )

    user_id = user.get("user_id") or str(user["_id"])
    now = datetime.now(timezone.utc)

    # Audit log
    await db.audit_logs.insert_one({
        "user_id": user_id,
        "action": "USER_LOGIN",
        "timestamp": now,
        "status": "SUCCESS",
    })

    token = create_access_token({
        "sub": user["email"],
        "user_id": user_id,
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "full_name": user.get("full_name", ""),
            "email": user.get("email"),
            "role": user.get("role", "analyst"),
            "created_at": user.get("created_at", now),
            "account_status": user.get("account_status", "active"),
            "notification_preferences": (
                user.get(
                    "notification_preferences",
                    {
                        "alerts": True,
                        "reports": True,
                    },
                )
            ),
        },
    }


@router.get(
    "/me",
    response_model=UserResponse,
)
async def get_me(
    current_user: dict = Depends(get_current_user),
):
    return {
        "id": get_user_id(current_user),
        "full_name": current_user.get("full_name", ""),
        "email": current_user.get("email"),
        "role": current_user.get("role", "analyst"),
        "created_at": current_user.get("created_at"),
        "account_status": current_user.get("account_status", "active"),
        "notification_preferences": (
            current_user.get(
                "notification_preferences",
                {
                    "alerts": True,
                    "reports": True,
                },
            )
        ),
    }


@router.put("/settings")
async def update_settings(
    update_data: UserUpdateSettings,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        )

    user_id = get_user_id(current_user)

    user_record = await db.users.find_one({
        "user_id": user_id
    })

    if not user_record:
        raise HTTPException(
            status_code=404,
            detail="User account not found",
        )

    update_fields = {}

    # Update full name
    if update_data.full_name is not None:
        full_name = update_data.full_name.strip()

        if not full_name:
            raise HTTPException(
                status_code=400,
                detail="Full name cannot be empty",
            )

        update_fields["full_name"] = full_name

    # Update notification preferences without overwriting
    # preferences that were not included in the request.
    if (
        update_data.notification_alerts is not None
        or update_data.notification_reports is not None
    ):
        current_preferences = user_record.get(
            "notification_preferences",
            {
                "alerts": True,
                "reports": True,
            },
        )

        new_preferences = {
            "alerts": current_preferences.get("alerts", True),
            "reports": current_preferences.get("reports", True),
        }

        if update_data.notification_alerts is not None:
            new_preferences["alerts"] = (
                update_data.notification_alerts
            )

        if update_data.notification_reports is not None:
            new_preferences["reports"] = (
                update_data.notification_reports
            )

        update_fields["notification_preferences"] = new_preferences

    # Update scan retention period
    if update_data.scan_retention_days is not None:
        update_fields["scan_retention_days"] = (
            update_data.scan_retention_days
        )

    # Change password
    if update_data.new_password:
        if not update_data.current_password:
            raise HTTPException(
                status_code=400,
                detail="Current password is required to set a new password",
            )

        if not verify_password(
            update_data.current_password,
            user_record.get("password_hash", ""),
        ):
            raise HTTPException(
                status_code=400,
                detail="Current password verification failed",
            )

        is_valid, msg = validate_password_strength(
            update_data.new_password
        )

        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=msg,
            )

        update_fields["password_hash"] = hash_password(
            update_data.new_password
        )

    # Save changes
    if update_fields:
        await db.users.update_one(
            {"user_id": user_id},
            {"$set": update_fields},
        )

        await db.audit_logs.insert_one({
            "user_id": user_id,
            "action": "SETTINGS_UPDATED",
            "timestamp": datetime.now(timezone.utc),
            "status": "SUCCESS",
        })

    return {
        "message": "Settings updated successfully"
    }


@router.post("/logout")
async def logout(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    user_id = get_user_id(current_user)

    if db is not None:
        await db.audit_logs.insert_one({
            "user_id": user_id,
            "action": "USER_LOGOUT",
            "timestamp": datetime.now(timezone.utc),
            "status": "SUCCESS",
        })

    return {
        "message": "Logged out successfully"
    }