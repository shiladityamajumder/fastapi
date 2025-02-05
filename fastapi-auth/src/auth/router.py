# src/auth/router.py

# FastAPI imports
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# SQLAlchemy imports
from sqlalchemy.orm import Session

# Local application imports
from .schemas import UserCreateSchema, UserResponseSchema, RegisterResponseWrapper
from .service import create_user
from .dependencies import get_db


# ? Initialize the router for authentication
router = APIRouter(prefix="/auth", tags=["Authentication"])


# *********** ========== Authentication Router ========== ***********
@router.post("/register", response_model=RegisterResponseWrapper, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreateSchema, db: Session = Depends(get_db)):
    """
    Register a new user.

    Args:
        user_data (User CreateSchema): The data for creating a new user.
        db (Session): The database session.

    Returns:
        dict: A response containing user data and tokens.

    Raises:
        HTTPException: If registration fails due to validation errors or server issues.
    """

    try:
        # Call the create_user function to create the user and get the response
        user_response = create_user(db, user_data)
    
        return {
            'data': {
                'refresh': user_response['refresh_token'],
                'access': user_response['access_token'],
                "user": {
                    "id": str(user_response["user"].id),
                    "username": user_response["user"].username,
                    "email": user_response["user"].email,
                    "full_name": user_response["user"].full_name,
                    "last_login": user_response["user"].last_login,
                    "is_superuser": user_response["user"].is_superuser,
                    "is_staff": user_response["user"].is_staff,
                    "date_joined": user_response["user"].date_joined,
                    "is_active": user_response["user"].is_active,
                    "created_at": user_response["user"].created_at,
                    "updated_at": user_response["user"].updated_at,
                    "country_code": user_response["user"].country_code,
                    "phone_number": user_response["user"].phone_number,
                    "address": user_response["user"].address,
                    "city": user_response["user"].city,
                    "state": user_response["user"].state,
                    "zip_code": user_response["user"].zip_code,
                    "country": user_response["user"].country,
                    "profile_picture": user_response["user"].profile_picture,
                    "bio": user_response["user"].bio,
                    "is_verified": user_response["user"].is_verified,
                    "is_push_notification_enabled": user_response["user"].is_push_notification_enabled,
                    "is_email_notification_enabled": user_response["user"].is_email_notification_enabled,
                    "is_sms_notification_enabled": user_response["user"].is_sms_notification_enabled,
                    "is_two_factor_enabled": user_response["user"].is_two_factor_enabled,
                    "role": user_response["user"].role,
                },
                "status": "success",
                "code": status.HTTP_201_CREATED
            },
            "message": "Registration successful",
            "status": True
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "data": {
                    "details": str(e),
                    "status": "error",
                    "code": status.HTTP_400_BAD_REQUEST
                },
                "message": "Registration failed",
                "status": False
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "data": {
                    "details": str(e),
                    "status": "error",
                    "code": status.HTTP_500_INTERNAL_SERVER_ERROR
                },
                "message": "Registration failed",
                "status": False
            }
        )
# *********** ========== End of Authentication Router ========== ***********