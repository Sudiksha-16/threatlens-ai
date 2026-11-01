import bcrypt
import re


def hash_password(password: str) -> str:
    if len(password.encode("utf-8")) > 72:
        raise ValueError(
            "Password cannot exceed 72 bytes."
        )

    salt = bcrypt.gensalt(rounds=12)

    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        salt,
    )

    return hashed.decode("utf-8")


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    try:
        if len(plain_password.encode("utf-8")) > 72:
            return False

        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )

    except (ValueError, TypeError, AttributeError):
        return False


def validate_password_strength(
    password: str,
) -> tuple[bool, str]:

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if len(password.encode("utf-8")) > 72:
        return False, "Password cannot exceed 72 bytes."

    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."

    return True, ""