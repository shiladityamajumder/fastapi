# src/auth/router.py

# FastAPI imports
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# SQLAlchemy imports
from sqlalchemy.orm import Session

# Third-party imports
from pydantic import ValidationError

# Local application imports
from .schemas import UserCreateSchema, UserAuthResponseSchema, AuthResponseWrapper, AuthTokensSchema, UserResponseSchema, ErrorResponseWrapper, ErrorDetails
from .service import create_user
from .dependencies import get_db


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
                    details="Invalid data format",
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
                    details="An unexpected error occurred",
                    status="error",
                    code=status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                message="Registration failed",
                status=False
            )
        )
# *********** ========== End ========== ***********