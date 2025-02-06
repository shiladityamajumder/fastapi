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
from .schemas import UserCreateSchema, UserAuthResponseSchema, AuthResponseWrapper, AuthTokensSchema, UserResponseSchema, ErrorResponseWrapper, ErrorDetails, UserLoginSchema, LogoutRequestSchema, LogoutResponseWrapper, LogoutResponseData
from .service import create_user, authenticate_user, logout_user
from .dependencies import get_db
from .utils import get_current_user
from .constants import ERROR_MESSAGES

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
        dict: A response containing user data and tokens.

    Raises:
        HTTPException: If registration fails due to validation errors or server issues.
    """

    try:
        # Validate and create the user using the service function
        user_response = create_user(db, user_data)
    
        # Return the response with user data and tokens
        return {
            "data": UserAuthResponseSchema(
                tokens=AuthTokensSchema(
                    access=user_response['access_token'],
                    refresh=user_response['refresh_token']
                ),
                user=UserResponseSchema.model_validate(user_response['user']),  # Using model_validate now
                status="success",
                code=status.HTTP_201_CREATED
            ),
            "message": "Registration successful",
            "status": True
        }
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
        dict: A response containing user data and tokens.

    Raises:
        HTTPException: If authentication fails due to invalid credentials or server issues.
    """

    try:
        # Authenticate the user using the service function
        auth_response = authenticate_user(db, login_data)
        
        # Return the response with user data and tokens
        return {
            "tokens": AuthTokensSchema(
                access=auth_response['access_token'],
                refresh=auth_response['refresh_token']
            ),
            "user": UserResponseSchema.model_validate(auth_response['user']),  # Using model_validate now
            "status": "success",
            "code": status.HTTP_200_OK
        }
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
async def logout(logout_data: LogoutRequestSchema, authorization: str = Header(None), db: Session = Depends(get_db)):
    """
    Logs out a user by blacklisting their refresh token and invalidating the access token.

    Args:
        logout_data (LogoutRequestSchema): The request body containing the refresh token.
        authorization (str): The Bearer token from the request headers.
        db (Session): The database session.

    Returns:
        LogoutResponseWrapper: The response object with status and message.

    Raises:
        HTTPException: If the access token is invalid or the refresh token is not found.
    """
    try:
        return logout_user(db, logout_data, authorization)
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