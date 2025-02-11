# src/auth/router.py

# FastAPI imports
from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# SQLAlchemy imports
from sqlalchemy.orm import Session

# Third-party imports
from pydantic import ValidationError

# Local application imports
from .models import User, Token
from .schemas import (
    UserCreateSchema, UserResponseSchema, AuthTokensSchema, UserAuthResponseSchema, AuthResponseWrapper, 
    UserLoginSchema, ProfileUpdateRequestSchema, UserProfileResponseData, UserProfileResponseWrapper, 
    ChangePasswordRequestSchema, ChangePasswordResponseData, ChangePasswordResponseWrapper, 
    PasswordResetRequestSchema, PasswordResetRequestResponseData, PasswordResetRequestResponseWrapper, 
    ResetPasswordWithTokenRequestSchema, ResetPasswordResponseData, ResetPasswordResponseWrapper, 
    LogoutRequestSchema, LogoutResponseData, LogoutResponseWrapper, 
    RefreshTokenRequestSchema, RefreshTokenRegenerateSchema,
    ErrorDetails, ErrorResponseWrapper,
    )
from .service import ( 
    create_user, authenticate_user, logout_user, change_password_service, 
    send_password_reset_otp_service, reset_password_service, 
    get_user_profile_service, update_user_profile_service,
    refresh_access_token, regenerate_access_token,
    )
from .dependencies import get_db
from .utils import get_current_user
from .constants import ERROR_MESSAGES
from .permissions import is_authenticated
import traceback  # Add this for detailed error logs


# ? Initialize the router for authentication
router = APIRouter(prefix="/auth", tags=["Authentication"])


# *********** ========== Registration Router ========== ***********
@router.post("/register", response_model=AuthResponseWrapper, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserCreateSchema, db: Session = Depends(get_db)):
    """
    Register a new user.

    Args:
        user_data (UserCreateSchema): The data for creating a new user.
        db (Session): The database session.

    Returns:
        AuthResponseWrapper: The response object with user data, tokens, and status.

    Raises:
        HTTPException: If registration fails due to validation errors or server issues.
    """

    try:
        # Validate and create the user using the service function
        return create_user(db, user_data)  # Simply return the response from the service
    except ValueError as e:
        # Specific user registration failure due to validation errors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_400_BAD_REQUEST
                ),
                message="Registration failed due to validation errors",
                status=False
            )
        )
    except ValidationError as e:
        # Schema validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["invalid_data_format"],
                    status="error",
                    code=status.HTTP_422_UNPROCESSABLE_ENTITY
                ),
                message=str(e),
                status=False
            )
        )
    except Exception as e:
        # Catch all unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Registration failed",
                status=False
            )
        )
# *********** ========== End ========== ***********


# *********** ========== Login Router ========== ***********
@router.post("/login", response_model=AuthResponseWrapper, status_code=status.HTTP_200_OK)
async def login_user(login_data: UserLoginSchema, db: Session = Depends(get_db)):
    """
    Authenticate a user and generate access and refresh tokens.

    Args:
        login_data (UserLoginSchema): The login data containing email and password.
        db (Session): The database session.

    Returns:
        AuthResponseWrapper: The response object with user data, tokens, and status.

    Raises:
        HTTPException: If authentication fails due to invalid credentials or server issues.
    """

    try:
        # Authenticate the user using the service function
        auth_response = authenticate_user(db, login_data)  # Await the coroutine
        return auth_response  # Simply return the response from the service
    
    except ValueError as e:
        # Specific authentication failure due to invalid credentials
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_401_UNAUTHORIZED
                ),
                message="Authentication failed due to invalid credentials",
                status=False
            ).model_dump()  # Convert to dictionary
        )
    except ValidationError as e:
        # Schema validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["invalid_data_format"],
                    status="error",
                    code=status.HTTP_422_UNPROCESSABLE_ENTITY
                ),
                message=str(e),
                status=False
            ).model_dump()  # Convert to dictionary
        )
    except Exception as e:
        # Catch all unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Authentication failed",
                status=False
            ).model_dump()  # Convert to dictionary
        )
# *********** ========== End ========== ***********


# *********** ========== Logout Router ========== ***********
@router.post("/logout", response_model=LogoutResponseWrapper, status_code=status.HTTP_200_OK)
async def logout(logout_data: LogoutRequestSchema, user: User = Depends(is_authenticated), db: Session = Depends(get_db)):
    """
    Logs out a user by blacklisting their refresh token and invalidating the access token.

    Args:
        logout_data (LogoutRequestSchema): The request body containing the refresh token.
        user (User): The authenticated user (from is_authenticated dependency).
        db (Session): The database session.

    Returns:
        LogoutResponseWrapper: The response object with status and message.

    Raises:
        HTTPException: If the access token is invalid or the refresh token is not found.
    """
    try:
        return logout_user(db, user, logout_data)  # Pass the user object instead of the authorization header
    except ValueError as e:
        # Specific logout failure due to invalid access token or refresh token
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_400_BAD_REQUEST
                ),
                message="Logout failed",
                status=False
            ).model_dump()  # Convert to dictionary
        )
    except ValidationError as e:
        # Schema validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["invalid_data_format"],
                    status="error",
                    code=status.HTTP_422_UNPROCESSABLE_ENTITY
                ),
                message=str(e),
                status=False
            ).model_dump()  # Convert to dictionary
        )
    except Exception as e:
        # Catch all unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Logout failed",
                status=False
            ).model_dump()  # Convert to dictionary
        )
# *********** ========== End ========== ***********


# *********** ========== Change Password Router ========== ***********
@router.post("/change-password", response_model=ChangePasswordResponseWrapper, status_code=status.HTTP_200_OK)
async def change_password(change_password_data: ChangePasswordRequestSchema, user: User = Depends(is_authenticated), db: Session = Depends(get_db)):
    """
    API endpoint to allow an authenticated user to change their password.

    Args:
        change_password_data (ChangePasswordRequestSchema): The request body containing passwords.
        user (User): The authenticated user.
        db (Session): The database session.

    Returns:
        ChangePasswordResponseWrapper: The response object with status and message.
    """
    try:
        return change_password_service(db, user, change_password_data)
    except ValueError as e:
        # Handle specific password change failures
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_400_BAD_REQUEST
                ),
                message="Change password failed",
                status=False
            ).model_dump()
        )
    except ValidationError as e:
        # Handle schema validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["invalid_data_format"],
                    status="error",
                    code=status.HTTP_422_UNPROCESSABLE_ENTITY
                ),
                message=str(e),
                status=False
            ).model_dump()
        )
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Change password failed",
                status=False
            ).model_dump()
        )
# *********** ========== End ========== ***********


# *********** ========== Send Password Reset OTP Router ========== ***********
@router.post("/send-password-reset-otp", response_model=PasswordResetRequestResponseWrapper, status_code=status.HTTP_200_OK)
async def send_reset_otp(request_data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    try:
        return send_password_reset_otp_service(db, request_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(details=str(e), status="error", code=status.HTTP_400_BAD_REQUEST),
                message="Failed to send OTP",
                status=False
            ).model_dump()
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(details="Unexpected error", status="error", code=status.HTTP_500_INTERNAL_SERVER_ERROR),
                message="Failed to send OTP",
                status=False
            ).model_dump()
        )
# *********** ========== End ========== ***********


# *********** ========== Reset Password Router ========== ***********
@router.post("/reset-password", response_model=ResetPasswordResponseWrapper, status_code=status.HTTP_200_OK)
async def reset_password(request_data: ResetPasswordWithTokenRequestSchema, db: Session = Depends(get_db)):
    try:
        return reset_password_service(db, request_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(details=str(e), status="error", code=status.HTTP_400_BAD_REQUEST),
                message="Password reset failed",
                status=False
            ).model_dump()
        )
    except Exception:
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(details="Unexpected error", status="error", code=status.HTTP_500_INTERNAL_SERVER_ERROR),
                message="Password reset failed",
                status=False
            ).model_dump()
        )
# *********** ========== End ========== ***********


# *********** ========== Get User Profile ========== ***********
@router.get("/profile", response_model=UserProfileResponseWrapper, status_code=status.HTTP_200_OK)
async def get_user_profile(user: User = Depends(is_authenticated), db: Session = Depends(get_db)):
    """
    Get the currently authenticated user's profile.

    Args:
        user (User): The authenticated user.
        db (Session): The database session.

    Returns:
        UserProfileResponseWrapper: The user's profile data.

    Raises:
        HTTPException: If user retrieval fails.
    """

    try:
        return get_user_profile_service(db, user)
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_404_NOT_FOUND
                ),
                message="User not found",
                status=False
            ).model_dump()  # Convert to dictionary
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Failed to retrieve user profile",
                status=False
            ).model_dump()  # Convert to dictionary
        )
# *********** ========== End ========== ***********


# *********** ========== Update User Profile ========== ***********
@router.patch("/update-profile", response_model=UserProfileResponseWrapper, status_code=status.HTTP_200_OK)
async def update_user_profile(update_data: ProfileUpdateRequestSchema, user: User = Depends(is_authenticated), db: Session = Depends(get_db)):
    """
    Update the currently authenticated user's profile.

    Args:
        update_data (ProfileUpdateRequestSchema): The updated profile data.
        user (User): The authenticated user.
        db (Session): The database session.

    Returns:
        UserProfileResponseWrapper: The updated user's profile.

    Raises:
        HTTPException: If the update fails.
    """

    try:
        return update_user_profile_service(db, user, update_data)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_400_BAD_REQUEST
                ),
                message="Profile update failed",
                status=False
            ).model_dump()
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Profile update failed",
                status=False
            ).model_dump()
        )
# *********** ========== End ========== ***********


# *********** ========== Refresh Access Token Router ========== ***********
@router.post("/token/refresh", response_model=AuthResponseWrapper, status_code=status.HTTP_200_OK)
async def refresh_access_token_route(refresh_data: RefreshTokenRequestSchema, db: Session = Depends(get_db)):
    """
    Refresh the access token using a valid refresh token.

    Args:
        refresh_data (RefreshTokenRequestSchema): The request body containing the refresh token.
        db (Session): The database session.

    Returns:
        AuthResponseWrapper: The response object containing the new access token and user details.

    Raises:
        HTTPException: If the refresh token is invalid or expired.
    """
    
    try:
        # Call the service to refresh the access token
        response = refresh_access_token(db, refresh_data)
        return response  # Return the service response directly

    except ValueError as e:
        # Specific failure due to invalid or expired token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_401_UNAUTHORIZED
                ),
                message="Token refresh failed",
                status=False
            ).model_dump()
        )

    except ValidationError as e:
        # Schema validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["invalid_data_format"],
                    status="error",
                    code=status.HTTP_422_UNPROCESSABLE_ENTITY
                ),
                message=str(e),
                status=False
            ).model_dump()
        )

    except Exception as e:
        # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Token refresh failed due to an internal error",
                status=False
            ).model_dump()
        )
# *********** ========== End ========== ***********


# *********** ========== Regenerate Access Token Router ========== ***********
@router.post("/token/regenerate", response_model=AuthResponseWrapper, status_code=status.HTTP_200_OK)
async def regenerate_access_token_route(regenerate_data: RefreshTokenRegenerateSchema, db: Session = Depends(get_db)):
    """
    Regenerate a new access token using a valid refresh token and token regeneration code.

    Args:
        regenerate_data (RefreshTokenRegenerateSchema): The request body containing the refresh token and regeneration code.
        db (Session): The database session.

    Returns:
        AuthResponseWrapper: The response object containing the new access token and user details.

    Raises:
        HTTPException: If the refresh token or regeneration code is invalid.
    """

    try:
        # Call the service to regenerate the access token
        response = regenerate_access_token(db, regenerate_data)
        return response  # Return the service response directly

    except ValueError as e:
        # Specific failure due to invalid token or regeneration code
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=str(e),
                    status="error",
                    code=status.HTTP_401_UNAUTHORIZED
                ),
                message="Token regeneration failed",
                status=False
            ).model_dump()
        )

    except ValidationError as e:
        # Schema validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["invalid_data_format"],
                    status="error",
                    code=status.HTTP_422_UNPROCESSABLE_ENTITY
                ),
                message=str(e),
                status=False
            ).model_dump()
        )

    except Exception as e:
        # Catch-all for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponseWrapper(
                data=ErrorDetails(
                    details=ERROR_MESSAGES["unexpected_error"],
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Token regeneration failed due to an internal error",
                status=False
            ).model_dump()
        )
# *********** ========== End ========== ***********