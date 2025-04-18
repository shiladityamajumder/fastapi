# src/auth/schemas.py

# Standard library imports
import re
from datetime import datetime

# Third-party library imports
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator, constr
from pydantic_core.core_schema import FieldValidationInfo
from typing import Optional, Literal, List, Dict, Any

# Local application imports
from .constants import PASSWORD_REGEX, USERNAME_REGEX, ERROR_MESSAGES


# *********** ========== Schemas for Registration ========== ***********
# ? UserCreateSchema - Schema for creating a new user => Request Body
class UserCreateSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=USERNAME_REGEX)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)
    country_code: Optional[str] = Field(None, max_length=5)
    phone_number: Optional[str] = Field(None, max_length=20)
    role: Optional[str] = Field(None)

    # ? Convert email to lowercase before validation
    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        return value.lower().strip() if value else value
    
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
    def validate_username(cls, value: str) -> str:
        value = value.lower()  # Automatically convert to lowercase
        if not re.match(USERNAME_REGEX, value):
            raise ValueError(ERROR_MESSAGES["invalid_username"])
        return value
    
    # ? Field Validator for email
    @field_validator('email')
    def validate_email(cls, values):
        if not values:
            raise ValueError(ERROR_MESSAGES["email_required"])
        return values
    
    # ? Field Validator for full_name
    @field_validator('full_name')
    def validate_full_name(cls, values):
        if not values:
            raise ValueError(ERROR_MESSAGES["full_name_required"])
        return values
    
    # ? Field Validator for role
    # * Newly created user's role
    @field_validator('role')
    def validate_role(cls, values):
        allowed_roles = {"user", "moderator"}
        if values and values not in allowed_roles:
            raise ValueError(ERROR_MESSAGES["invalid_role"])
        return values

    class Config:
        orm_mode = True  # Allows compatibility with ORM models


# ! UserMinimalSchema - Minimal schema for user data => Response Body
# * Used in various places where only basic user info is needed
class UserMinimalSchema(BaseModel):
    id: str
    username: str
    full_name: str
    email: EmailStr

    class Config:
        orm_mode = True
        from_attributes = True


# ! UserResponseSchema - Schema for user response => Response Body
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
    updated_at: Optional[datetime] = None
    country_code: Optional[str] = None
    phone_number: Optional[str] = None
    job_title: Optional[str] = None
    department: Optional[str] = None
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
    is_mfa_enabled: bool  # Renamed field for MFA
    preferred_mfa_method: Optional[str] = None
    role: str
    created_by: Optional[UserMinimalSchema] = None # User who created this user

    class Config:
        orm_mode = True  # Allows compatibility with ORM models
        from_attributes = True  # Enabling the new from_attributes feature


# ! AuthTokensSchema - Schema for authentication tokens => Response Body
class AuthTokensSchema(BaseModel):
    refresh: str
    access: str


# ! UserAuthResponseSchema - Response schema for authentication-related endpoints (login, registration) => Response Body
class UserAuthResponseSchema(BaseModel):
    tokens: AuthTokensSchema
    user: UserResponseSchema
    session_id: str
    status: str
    code: int


# ! AuthResponseWrapper - Wrapper for authentication responses => Response Body
class AuthResponseWrapper(BaseModel):
    data: UserAuthResponseSchema
    message: str
    status: bool
# *********** ========== End ========== *********** 










# *********** ========== Schemas for User Login, Profile Update ========== ***********
# ? UserLoginSchema - Schema for user login => Request Body => Request Body
class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    # ? Convert email to lowercase before validation
    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        return value.lower().strip() if value else value

    # ? Field Validator for password
    @field_validator("password")
    def validate_password(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["password_required"])
        return value
    
    # ? Field Validator for email
    @field_validator("email")
    def validate_email(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["email_required"])
        return value
    
    class Config:
        orm_mode = True


# ? ProfileUpdateRequestSchema - Schema for user profile update => Request Body
class ProfileUpdateRequestSchema(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    country_code: Optional[str] = None
    phone_number: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None
    profile_picture: Optional[str] = None
    bio: Optional[str] = None
    is_mfa_enabled: Optional[bool] = None
    preferred_mfa_method: Optional[str] = None
    is_superuser: Optional[bool] = None
    is_staff: Optional[bool] = None
    role: Optional[str] = None
    is_verified: Optional[bool] = None
    is_push_notification_enabled: Optional[bool] = None
    is_email_notification_enabled: Optional[bool] = None
    is_sms_notification_enabled: Optional[bool] = None

    @field_validator("username")
    def validate_username(cls, value):
        if value and not re.match(USERNAME_REGEX, value):
            raise ValueError(ERROR_MESSAGES["invalid_username"])
        return value

    @field_validator("phone_number")
    def validate_phone_number(cls, value):
        if value and not value.isdigit():
            raise ValueError(ERROR_MESSAGES["invalid_phone_number"])
        return value

    class Config:
        orm_mode = True  # Allows compatibility with ORM models


# ? RefreshTokenRequestSchema - Schema for requesting a new access token using refresh_token => Request Body
class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str = Field(..., title="Refresh Token", description="Valid refresh token to obtain a new access token.")

    class Config:
        orm_mode = True


# ? RefreshTokenRegenerateSchema - Schema for regenerating refresh token with token_regeneration_code => Request Body
class RefreshTokenRegenerateSchema(BaseModel):
    refresh_token: str = Field(..., title="Refresh Token", description="Valid refresh token for re-authentication.")
    token_regeneration_code: str = Field(..., title="Token Regeneration Code", description="Secure code used to regenerate refresh token.")

    class Config:
        orm_mode = True


# ! UserProfileResponseData - Data section inside the response => Response Body
# ? Used UserResponseSchema from the above section
class UserProfileResponseData(BaseModel):
    user: UserResponseSchema
    status: str
    code: int


# ! UserProfileResponseWrapper - Wrapper for profile-related responses => Response Body
class UserProfileResponseWrapper(BaseModel):
    data: UserProfileResponseData
    message: str
    status: bool
# *********** ========== End ========== ***********










# *********** ========== Schemas for Change Password ========== ***********
# ? ChangePasswordRequestSchema - Schema for user change password request => Request Body
class ChangePasswordRequestSchema(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)

    # ? Model Validator for checking if passwords match and valid password format
    @model_validator(mode="before")
    def check_passwords_match(cls, values):
        new_password = values.get("new_password")
        confirm_password = values.get("confirm_password")
        
        if new_password and confirm_password:
            if new_password != confirm_password:
                raise ValueError(ERROR_MESSAGES["passwords_not_same"])
            if not re.match(PASSWORD_REGEX, new_password):
                raise ValueError(ERROR_MESSAGES["invalid_password"])
        
        return values
    
    # ? Field Validator for current_password
    @field_validator("current_password")
    def validate_current_password(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["current_password_required"])
        return value

    # ? Field Validator for new_password
    @field_validator("new_password")
    def validate_new_password(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["new_password_required"])
        return value

    # ? Field Validator for confirm_password
    @field_validator("confirm_password")
    def validate_confirm_password(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["confirm_password_required"])
        return value


# ! ChangePasswordResponseData - Data section inside the response => Response Body
class ChangePasswordResponseData(BaseModel):
    status: str
    code: int


# ! ChangePasswordResponseWrapper - Wrapper for change password response => Response Body
class ChangePasswordResponseWrapper(BaseModel):
    data: ChangePasswordResponseData
    message: str
    status: bool
# *********** ========== End ========== ***********










# *********** ========== Schemas for Password Reset ========== ***********
# ? PasswordResetRequestSchema - Schema for password reset request (email based) => Request Body
class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    def validate_email(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["email_required"])
        return value


# ! PasswordResetRequestResponseData - Data for password reset request response => Response Body
class PasswordResetRequestResponseData(BaseModel):
    email: EmailStr
    status: str
    code: int


# ! PasswordResetRequestResponseWrapper - Wrapper for password reset request response => Response Body
class PasswordResetRequestResponseWrapper(BaseModel):
    data: PasswordResetRequestResponseData
    message: str
    status: bool


# ? ResetPasswordWithTokenRequestSchema - Schema for resetting password using token => Request Body
class ResetPasswordWithTokenRequestSchema(BaseModel):
    email: EmailStr
    otp: int
    new_password: str = Field(..., min_length=8, max_length=128)

    # ? Field Validator for email
    @field_validator("email")
    def validate_email(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["email_required"])
        return value

    # ? Field Validator for token
    @field_validator("otp")
    def validate_otp(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["otp_required"])
        return value

    # ? Field Validator for new_password
    @field_validator("new_password")
    def validate_new_password(cls, value):
        if not re.match(PASSWORD_REGEX, value):
            raise ValueError(ERROR_MESSAGES["invalid_password"])
        return value


# ! ResetPasswordResponseData - Data for password reset completion response => Response Body
class ResetPasswordResponseData(BaseModel):
    status: str
    code: int


# ! ResetPasswordResponseWrapper - Wrapper for password reset response => Response Body
class ResetPasswordResponseWrapper(BaseModel):
    data: ResetPasswordResponseData
    message: str
    status: bool
# *********** ========== End ========== *********** 










# *********** ========== Schemas for Logout ========== ***********
# ? LogoutRequestSchema - Schema for logout request => Request Body
class LogoutRequestSchema(BaseModel):
    refresh_token: str  # Refresh token sent in the request body

    @field_validator("refresh_token")
    def validate_refresh_token(cls, value):
        if not value:
            raise ValueError(ERROR_MESSAGES["refresh_token_required"])
        return value


# ! LogoutResponseData - Data section inside the response => Response Body
class LogoutResponseData(BaseModel):
    status: str
    code: int


# ! LogoutResponseWrapper - Wrapper for logout response => Response Body
class LogoutResponseWrapper(BaseModel):
    data: LogoutResponseData
    message: str
    status: bool
# *********** ========== End ========== *********** 










# *********** ========== Schemas for Session Management ========== ***********
# ? SessionCreateSchema - Schema for creating a new session => Request Body

class SessionCreateSchema(BaseModel):
    user_id: str = Field(..., description="The ID of the user for whom the session is created.")
    device_info: str = Field(..., description="Information about the device used for the session.")
    ip_address: str = Field(..., description="The IP address from which the user logged in.")

    class Config:
        orm_mode = True  # Allows compatibility with ORM models


# ! SessionResponseSchema - Schema for session response => Response Body
class SessionResponseSchema(BaseModel):
    id: str
    user_id: str
    device_info: str
    ip_address: str
    login_time: datetime
    last_activity: datetime
    is_active: bool

    class Config:
        orm_mode = True  # Allows compatibility with ORM models


# ! ListSessionsResponseSchema - Wrapper for listing sessions => Response Body
class ListSessionsResponseSchema(BaseModel):
    sessions: list[SessionResponseSchema]
    message: str
    status: bool


# ! RevokeSessionRequestSchema - Schema for revoking a session => Request Body
class RevokeSessionRequestSchema(BaseModel):
    session_id: str = Field(..., description="The ID of the session to revoke.")

    class Config:
        orm_mode = True  # Allows compatibility with ORM models


# ! RevokeSessionResponseSchema - Response schema for revoking a session => Response Body
class RevokeSessionResponseSchema(BaseModel):
    message: str
    status: bool


# ! SessionWrapper - Wrapper for session-related responses => Response Body
class SessionWrapper(BaseModel):
    data: Optional[SessionResponseSchema] = None
    message: str
    status: bool
# *********** ========== End ========== *********** 










# *********** ========== Schemas for Error => Response Body ========== ***********
# ? Define the structure for the error details
class ErrorDetails(BaseModel):
    details: str  # The error message or specific issue
    status: Literal['error']  # The status must be "error"
    code: int  # The HTTP status code, e.g., 400 for Bad Request, 404 for Not Found, etc.


# ? The wrapper for error responses
class ErrorResponseWrapper(BaseModel):
    data: ErrorDetails  # The actual error details
    message: str  # A general error message, e.g., "Validation error", "Server error"
    status: bool  # False indicates an error status
# *********** ========== End ========== ***********










# *********** ========== Schemas for MFA ========== ***********
# TODO=> Common CRUD Response Wrapper (for all CRUD operations)
class CRUDResponseWrapper(BaseModel):
    data: Optional[Dict[str, Any]] = None  # Holds response data dynamically
    message: str  # Custom message for each CRUD operation
    status: bool  # True if successful, False otherwise
    code: int = 200  # HTTP response code (default 200)


# ? Add MFA Schema => Request Body
class AddMFARequestSchema(BaseModel):
    mfa_type: str = Field(..., description="Type of MFA (e.g., 'sms', 'email', 'authenticator')")
    mfa_provider: str = Field(..., description="MFA provider (e.g., 'google', 'microsoft', 'email', 'sms')")
    device_id: Optional[str] = Field(None, description="Unique identifier for authenticator apps (if applicable)")
    mfa_device_name: Optional[str] = Field(None, description="Name for TOTP device (if applicable)")
    
    @field_validator("mfa_type")
    def validate_mfa_type(cls, value):
        valid_types = {"sms", "email", "authenticator"}
        if value not in valid_types:
            raise ValueError(f"Invalid MFA type. Choose from {valid_types}")
        return value

    @field_validator("mfa_provider")
    def validate_mfa_provider(cls, value):
        valid_providers = {"google", "microsoft", "email", "sms"}
        if value not in valid_providers:
            raise ValueError(f"Invalid MFA provider. Choose from {valid_providers}")
        return value


# ? Edit MFA Schema => Request Body
class EditMFARequestSchema(BaseModel):
    mfa_device_name: Optional[str] = Field(None, description="Updated name for MFA device")
    is_active: Optional[bool] = Field(None, description="Enable or disable MFA")
    preferred: Optional[bool] = Field(None, description="Set this as the preferred MFA method")


# ! MFA Response Schema (For a Single MFA Record) => Response Body
class MFAResponseSchema(BaseModel):
    id: str
    user_id: str
    mfa_type: str
    mfa_provider: str
    device_id: Optional[str] = None
    mfa_device_name: Optional[str] = None
    created_at: datetime
    last_modified_at: Optional[datetime] = None
    is_active: bool
    is_preferred: bool = Field(..., description="Indicates if this is the user's preferred MFA method")


# ! List MFA Response (For fetching all user MFA methods) => Response Body
class MFAListResponseSchema(BaseModel):
    total: int
    mfa_methods: List[MFAResponseSchema]


# ? Update MFA Settings => Request Body
class MFAUpdateSchema(BaseModel):
    is_mfa_enabled: bool
    preferred_mfa_method: Optional[str] = Field(None, description="Preferred MFA method (e.g., 'sms', 'email', 'authenticator')")


# ! Delete MFA Response Schema => Response Body
class DeleteMFAResponseSchema(BaseModel):
    message: str
    status: bool


# ! MFA Response Data - Holds the `user` and `mfa` details
class MFAResponseData(BaseModel):
    user: UserResponseSchema
    mfa_methods: List[MFAResponseSchema]


# ! Use Common CRUD Wrapper for Responses
class AddMFAResponse(CRUDResponseWrapper):
    data: Optional[MFAResponseSchema] = None
    message: str = "MFA method added successfully."


class EditMFAResponse(CRUDResponseWrapper):
    data: Optional[MFAResponseSchema] = None
    message: str = "MFA method updated successfully."


class ViewMFAResponse(CRUDResponseWrapper):
    data: Optional[MFAResponseData] = None
    message: str = "MFA details retrieved successfully."


class DeleteMFAResponse(CRUDResponseWrapper):
    data: Optional[dict] = None
    message: str = "MFA method deleted successfully."
# *********** ========== End ========== ***********