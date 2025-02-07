

# Standard library imports
from datetime import datetime, timezone
import os
import jwt
from typing import Optional
from fastapi import Depends, HTTPException, Header
from jwt import PyJWTError

# SQLAlchemy imports
from sqlalchemy.orm import Session

# Local application imports
from .models import User, Token  # Assuming your Token model is in a file named models.py
from .dependencies import get_db  # Import your DB session dependency



# Secret key and algorithm for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")  # Use a default for development
ALGORITHM = "HS256"


# *********** ========== Token Validation Utility ========== ***********
def validate_refresh_token(db: Session, token: str) -> bool:
    """
    Validates a refresh token by checking the database.

    Args:
        db (Session): The database session.
        token (str): The refresh token to validate.

    Returns:
        bool: True if the token is valid and not expired, False otherwise.
    """
    token_entry = db.query(Token).filter(Token.token == token).first()
    if token_entry and token_entry.expires_at > datetime.now(timezone.utc):
        return True
    return False
# *********** ========== End of Token Validation Utility ========== ***********


# *********** ========== Token Decoding Utility ========== ***********
def decode_access_token(token: str) -> dict:
    """
    Decodes and verifies an access token.

    Args:
        token (str): The JWT access token.

    Returns:
        dict: Decoded payload if valid.

    Raises:
        HTTPException: If the token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Ensure the token has not expired
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Access token has expired")

        # Ensure it is an access token (not a refresh token)
        if payload.get("token_type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        return payload
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")
# *********** ========== End of Token Decoding Utility ========== ***********


# *********** ========== Current User Dependency ========== ***********
def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    """
    FastAPI Dependency: Validates access token and retrieves the user.

    Args:
        authorization (str): The Bearer token from request headers.
        db (Session): The database session.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: If the token is invalid or user is not found.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid token scheme")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")

    # Decode the token
    payload = decode_access_token(token)

    # Extract user_id
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID not found in token")

    # Fetch the user from the database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user
# *********** ========== End of Current User Dependency ========== ***********