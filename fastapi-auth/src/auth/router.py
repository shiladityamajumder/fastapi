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
    ErrorDetails, ErrorResponseWrapper,
    )
from .service import ( 
    create_user, login_user, logout_user, change_password_service
    )
from .dependencies import get_db
from .utils import get_current_user
from .constants import ERROR_MESSAGES
from .permissions import is_authenticated


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
@router.post("/login", response_model=UserAuthResponseSchema, status_code=status.HTTP_200_OK)
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
        return login_user(db, login_data)  # Simply return the response from the service

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
                message="Authentication failed",
                status=False
            )
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
        return logout_user(db, logout_data, user)  # Pass the user object instead of the authorization header
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