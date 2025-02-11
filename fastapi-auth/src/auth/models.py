# src/auth/models.py

# Standard library imports
import os
import logging
import random
from datetime import datetime, timedelta, timezone

# Third-party library imports
import jwt
from argon2 import PasswordHasher
from sqlalchemy import Column, String, Boolean, DateTime, CheckConstraint, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

# Local application imports
from ..database import Base  # Import Base here
from .constants import USER_ID_COLUMN

# UUID generation
import uuid


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Load sensitive information from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")  # Use a default for development
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7 days

# Initialize the PasswordHasher
ph = PasswordHasher()

# *********** ========== Tables for authentications ========== ***********
# ? The User model is used to store user information in the database.
# ? It includes fields for the user's username, email, full name, password, and other details.
# ? The model also includes methods for password hashing, token generation, and other user-related operations. 
class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)  # For SQLite
    username = Column(String(150), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), index=True, nullable=False)
    password = Column(String, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    date_joined = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # * Optional Fields
    country_code = Column(String(5), nullable=True)
    phone_number = Column(String(20), nullable=True)  # Unique for OTP login

    # * MFA Fields
    is_mfa_enabled = Column(Boolean, default=False)

    # * Permissions and Roles
    is_superuser = Column(Boolean, default=False)
    is_staff = Column(Boolean, default=False)
    role = Column(String(50), nullable=False)

    # * Profile Fields
    address = Column(String(255), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    zip_code = Column(String(20), nullable=True)
    country = Column(String(100), nullable=True)
    profile_picture = Column(String(255), nullable=True)
    bio = Column(String(500), nullable=True)

    # * Notification Preferences
    is_verified = Column(Boolean, default=False)
    is_push_notification_enabled = Column(Boolean, default=True)
    is_email_notification_enabled = Column(Boolean, default=True)
    is_sms_notification_enabled = Column(Boolean, default=True)

    # * Token Regeneration Code
    token_regeneration_code = Column(String(255), nullable=True, unique=True) # ? This field is used for securely regenerating access or refresh tokens.
    
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint(
            "role IN ('user', 'admin', 'editor', 'moderator', 'superuser')",
            name="check_role_validity"
        ),
    )

    def __repr__(self):
        return f"<User  (id={self.id}, username={self.username}, email={self.email})>"

    def set_password(self, password: str) -> None:
        """Hashes and sets the user's password."""
        self.password = ph.hash(password)

    def verify_password(self, password: str) -> bool:
        """Verifies a plain password against the hashed password."""
        try:
            return ph.verify(self.password, password)
        except Exception as e:
            logger.error("Password verification failed: %s", e)
            return False

    def update_last_login(self) -> None:
        """Updates the last login timestamp."""
        self.last_login = datetime.now(timezone.utc)

    def generate_access_token(self) -> str:
        """Generates an access token for the user."""
        payload = {
            "token_type": "access",
            "sub": self.username,
            "user_id": self.id,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),
        }
        logger.info("Creating access token for user: %s", self.username)
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    def generate_refresh_token(self, db) -> str:
        """Generates a refresh token and invalidates the previous one."""
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        jti = str(uuid.uuid4())
        
        payload = {
            "token_type": "refresh",
            "sub": self.username,
            "user_id": self.id,
            "exp": expires_at,
            "iat": issued_at,
            "jti": jti,
        }
        refresh_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        # Invalidate old refresh tokens
        db.query(Token).filter(Token.user_id == self.id, Token.token_type == "refresh").update({"is_blacklisted": True})
        db.commit()

        # Save the token to the database
        token_entry = Token(
            user_id=self.id,
            token=refresh_token,
            token_type="refresh",
            jti=jti,
            issued_at=issued_at,
            expires_at=expires_at
        )
        db.add(token_entry)
        db.commit()

        logger.info("Creating refresh token for user: %s", self.username)
        return refresh_token

    def revoke_all_tokens(self, db):
        """Revokes all active tokens for the user."""
        db.query(Token).filter(Token.user_id == self.id, Token.is_active == True).update({"is_blacklisted": True, "is_active": False})
        db.commit()
        logger.info("Revoked all tokens for user: %s", self.username)

    @staticmethod
    def verify_access_token(token: str):
        """Verifies if the token is an access token and returns the payload."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("token_type") != "access":
                logger.warning("Invalid token type: Expected access token")
                return None
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Access token has expired")
            return None
        except jwt.JWTError as e:
            logger.error("Token decoding failed: %s", e)
            return None

    @staticmethod
    def verify_refresh_token(token: str, db):
        """Verifies if the token is a valid refresh token and checks for blacklisting."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("token_type") != "refresh":
                logger.warning("Invalid token type: Expected refresh token")
                return None
            
            jti = payload.get("jti")
            user_id = payload.get("user_id")

            # Check if the token exists and is not blacklisted
            stored_token = db.query(Token).filter(
                Token.user_id == user_id,
                Token.jti == jti,
                Token.token_type == "refresh",
                Token.is_blacklisted == False
            ).first()

            if not stored_token:
                logger.warning("Refresh token is invalid or blacklisted")
                return None

            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Refresh token has expired")
            return None
        except jwt.JWTError as e:
            logger.error("Token decoding failed: %s", e)
            return None
        
    def update_profile(self, full_name: str = None, email: str = None, **kwargs) -> None:
        """Updates the user's profile information."""
        if full_name:
            self.full_name = full_name
        if email:
            self.email = email
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def toggle_notification_preference(self, notification_type: str, enabled: bool) -> None:
        """Toggles notification preferences for the user."""
        if notification_type == "push":
            self.is_push_notification_enabled = enabled
        elif notification_type == "email":
            self.is_email_notification_enabled = enabled
        elif notification_type == "sms":
            self.is_sms_notification_enabled = enabled

    def has_role(self, role: str) -> bool:
        """Checks if the user has a specific role."""
        return self.role == role

    def is_active_user(self) -> bool:
        """Checks if the user account is active."""
        return self.is_active

    def hard_delete(self, db):
        """Permanently deletes the user from the database."""
        db.delete(self)
        db.commit()

    def soft_delete(self): 
        """Marks the user as inactive."""
        self.is_active = False
        self.updated_at = datetime.now(timezone.utc)


# ? The Token model is used to store refresh tokens for users.
# ? It includes fields for the user ID, token, token type, issued and expiry timestamps, and other details.
# ? The model also includes methods for token blacklisting and deletion.
class Token(Base):
    __tablename__ = "tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String, ForeignKey(USER_ID_COLUMN), nullable=False)
    token = Column(String, nullable=False)
    token_type = Column(String, nullable=False)  # 'access' or 'refresh'
    jti = Column(String, unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    issued_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_blacklisted = Column(Boolean, default=False)  # For blacklisting tokens
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_modified_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="tokens")

    def __repr__(self):
        return f"<Token (id={self.id}, user_id={self.user_id}, token_type={self.token_type}, expires_at={self.expires_at})>"

    def hard_delete(self, db):
        """Permanently deletes the token from the database."""
        db.delete(self)
        db.commit()

    def soft_delete(self):
        """Marks the token as inactive and blacklists it."""
        self.is_active = False
        self.is_blacklisted = True
        self.last_modified_at = datetime.now(timezone.utc)


# ? The OTP model is used to store OTP codes for phone login.
# ? It includes fields for the user ID, OTP code, expiry timestamp, and other details.
# ? The model also includes methods for OTP generation, validation, and deletion.
# OTP Model for Phone Login
class OTP(Base):
    __tablename__ = "otp_codes"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String, ForeignKey(USER_ID_COLUMN), nullable=False)
    otp_code = Column(String(6), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_modified_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)

    user = relationship("User")

    def __repr__(self):
        return f"<OTP (id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"
    
    @staticmethod
    def generate_otp():
        """Generates a 6-digit numeric OTP."""
        return str(random.randint(100000, 999999))

    def is_valid(self, provided_otp):
        """Checks if the OTP is valid (not expired, not used, and matches the provided OTP)."""
        return not self.is_used and self.expires_at > datetime.now(timezone.utc) and self.otp_code == provided_otp

    def hard_delete(self, db):
        """Permanently deletes the OTP from the database."""
        db.delete(self)
        db.commit()

    def soft_delete(self):
        """Marks the OTP as inactive."""
        self.is_active = False
        self.last_modified_at = datetime.now(timezone.utc)


# ? The MFA model is used to store multi-factor authentication settings for users.
# ? It includes fields for the user ID, MFA provider, secret key, and other details.
# ? The model also includes methods for hard and soft deletion of MFA settings.
class MFA(Base):
    __tablename__ = "mfa_settings"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String, ForeignKey(USER_ID_COLUMN), nullable=False)
    mfa_type = Column(String(20), nullable=False)  # e.g., 'sms', 'authenticator'
    mfa_provider = Column(String(20), nullable=False)
    mfa_secret = Column(String(255), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_modified_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)

    user = relationship("User")

    def __repr__(self):
        return f"<MFA (id={self.id}, user_id={self.user_id}, mfa_provider={self.mfa_provider})>"

    def hard_delete(self, db):
        """Permanently deletes the MFA settings from the database."""
        db.delete(self)
        db.commit()

    def soft_delete(self): 
        """Marks the MFA settings as inactive."""
        self.is_active = False
        self.last_modified_at = datetime.now(timezone.utc)


# ? The PasswordReset model is used to store password reset codes for users.
# ? It includes fields for the user ID, OTP code, expiry timestamp, and other details.
# ? The model also includes methods for OTP generation, validation, and deletion.
# Password Reset Model
class PasswordReset(Base):
    __tablename__ = "password_reset_codes"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String, ForeignKey(USER_ID_COLUMN), nullable=False)
    otp_code = Column(String(6), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_modified_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    
    user = relationship("User")
    
    @staticmethod
    def generate_otp():
        """Generates a 6-digit numeric OTP for password reset."""
        return str(random.randint(100000, 999999))
    
    def is_valid(self, provided_otp):
        expires_at = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return (
            not self.is_used and 
            self.is_active and
            expires_at > datetime.now(timezone.utc) 
            and int(self.otp_code) == int(provided_otp)
            )
    
    def hard_delete(self, db):
        """Permanently deletes the password reset code from the database."""
        db.delete(self)
        db.commit()

    def soft_delete(self):
        """Marks the password reset code as inactive."""
        self.is_active = False
        self.last_modified_at = datetime.now(timezone.utc)
# *********** ========== End ========== *********** 