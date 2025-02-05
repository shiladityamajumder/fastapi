# src/auth/service.py

# Standard library imports
from datetime import timedelta, timezone

# Third-party library imports
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

# Local application imports
from .models import User  # Importing the User model for database operations
from .schemas import UserCreateSchema  # Importing the schema for user creation validation
from .constants import ERROR_MESSAGES  # Importing error messages for user feedback


# *********** ========== User Authentication Service ========== ***********
def create_user(db: Session, user_data: UserCreateSchema):
    """
    Create a new user in the database.

    Args:
        db (Session): The database session.
        user_data (User CreateSchema): The data for creating a new user.

    Raises:
        ValueError: If the email or phone number already exists, or if the username is taken.

    Returns:
        dict: A dictionary containing the newly created user and their access and refresh tokens.
    """
    
    # Check if the email already exists
    existing_user_by_email = db.query(User).filter_by(email=user_data.email).first()
    if existing_user_by_email:
        raise ValueError(ERROR_MESSAGES["email_exists"])

    # Check if the phone number already exists
    if user_data.phone_number and user_data.country_code:
        existing_user_by_phone = db.query(User).filter_by(
            phone_number=user_data.phone_number,
            country_code=user_data.country_code
        ).first()
        if existing_user_by_phone:
            raise ValueError(ERROR_MESSAGES["phone_number_exists"])

    # Create a new user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        country_code=user_data.country_code,
        phone_number=user_data.phone_number,
        role="user",
    )
    
    # Set the user's password using the method from the User model
    new_user.set_password(user_data.password)

    db.add(new_user)
    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise ValueError(ERROR_MESSAGES["username_exists"])

    # Generate tokens using the method from the User model
    access_token = new_user.generate_access_token()
    refresh_token = new_user.generate_refresh_token(db)

    return {
        "user": new_user,
        "access_token": access_token,
        "refresh_token": refresh_token
    }
# *********** ========== End ========== ***********