
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import jwt

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.app.config.settings import settings
from backend.app.database.mongodb import get_database


security_bearer = HTTPBearer(auto_error=False)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = data.copy()

    now = datetime.now(timezone.utc)

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({
        "exp": expire,
        "iat": now,
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )

    return encoded_jwt


async def get_current_user_from_token_str(
    token: str,
) -> Dict[str, Any]:

    if not token or not isinstance(token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Decode and validate JWT
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )

        email = payload.get("sub")
        token_user_id = payload.get("user_id")

        if not isinstance(email, str) or not email.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        email = email.strip().lower()

        if token_user_id is not None and not isinstance(
            token_user_id, str
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token identity",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except HTTPException:
        raise

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Connect to database
    db = await get_database()

    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable",
        )

    # 3. Find authenticated user
    user = await db.users.find_one({
        "email": email
    })

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Verify token identity if present
    stored_user_id = user.get("user_id")

    if (
        token_user_id is not None
        and stored_user_id is not None
        and token_user_id != stored_user_id
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token identity",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 5. Check account status
    account_status = user.get("account_status", "active")

    if account_status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active. Contact administrator.",
        )

    # 6. Prepare user data
    user["_id"] = str(user["_id"])

    user.pop("password_hash", None)

    return user


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        security_bearer
    ),
) -> Dict[str, Any]:

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return await get_current_user_from_token_str(
        credentials.credentials
    )