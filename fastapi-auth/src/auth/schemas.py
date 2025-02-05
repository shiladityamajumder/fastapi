# src/auth/schemas.py

# Standard library imports
import re
from datetime import datetime

# Third-party library imports
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from pydantic_core.core_schema import FieldValidationInfo
from typing import Optional

# Local application imports
from .constants import PASSWORD_REGEX, USERNAME_REGEX, ERROR_MESSAGES


# *********** ========== Schemas (Field Validation) for authentications ==> Request Body ========== ***********
# ? UserCreateSchema - Schema for creating a new user
class UserCreateSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=USERNAME_REGEX)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)
    country_code: Optional[str] = Field(None, max_length=5)
    phone_number: Optional[str] = Field(None, max_length=20)

    # ? Model Validator for checking if passwords match
    @model_validator(mode="before")
    def check_passwords_match(cls, values):
        password = values.get("password")
        confirm_password = values.get("confirm_password")
        
        if password and confirm_password:
            if password != confirm_password:
                raise ValueError(ERROR_MESSAGES["passwords_do_not_match"])
            if not re.match(PASSWORD_REGEX, password):
                raise ValueError(ERROR_MESSAGES["invalid_password"])
        
        return values

    # ? Field Validator for username
    @field_validator('username')
    def validate_username(cls, v):
        if not re.match(USERNAME_REGEX, v):
            raise ValueError(ERROR_MESSAGES["invalid_username"])
        return v


# ? UserLoginSchema - Schema for user login
class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    def validate_password(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["password_required"])
        return value
# *********** ========== End ========== *********** 


# *********** ========== Schemas (Field Validation) for authentications ==> Response Body ========== ***********
# ? UserResponseSchema - Schema for user response
class UserResponseSchema(BaseModel):
    id: str
    username: str
    email: EmailStr
    full_name: str
    last_login: Optional[datetime] = None
    is_superuser: bool
    is_staff: bool
    date_joined: datetime
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None  # ✅ Fix: Allow None
    country_code: Optional[str] = None
    phone_number: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None
    profile_picture: Optional[str] = None
    bio: Optional[str] = None
    is_verified: bool
    is_push_notification_enabled: bool
    is_email_notification_enabled: bool
    is_sms_notification_enabled: bool
    is_two_factor_enabled: bool
    role: str

    class Config:
        orm_mode = True  # Allows compatibility with ORM models


# ? UserRegisterResponseSchema - Schema for user registration response
class UserRegisterResponseSchema(BaseModel):
    refresh: str
    access: str
    user: UserResponseSchema
    status: str
    code: int


# ? RegisterResponseWrapper - Wrapper for user registration response
class RegisterResponseWrapper(BaseModel):
    data: UserRegisterResponseSchema
    message: str
    status: bool
# *********** ========== End ========== *********** 