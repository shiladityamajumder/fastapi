# src/auth/utils.py

# Standard library imports
from datetime import datetime, timezone

# SQLAlchemy imports
from sqlalchemy.orm import Session

# Local application imports
from .models import Token  # Assuming your Token model is in a file named models.py

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