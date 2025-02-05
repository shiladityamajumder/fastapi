# src/auth/service.py

# Standard library imports
import re
from datetime import timedelta, timezone

# Third-party library imports
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

# Local application imports
from .models import User  # Importing the User model for database operations
from .schemas import UserCreateSchema  # Importing the schema for user creation validation
from .constants import ERROR_MESSAGES  # Importing error messages for user feedback


# *********** ========== User Registartion Service ========== ***********
def create_user(db: Session, user_data: UserCreateSchema):
    """
    Create a new user in the database.

    Args:
        db (Session): The database session.
        user_data (UserCreateSchema): The data for creating a new user.

    Raises:
        ValueError: If the email, phone number, or username already exists, 
                    or if the password validation fails.

    Returns:
        dict: A dictionary containing the newly created user and their access and refresh tokens.
    """

    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", user_data.email):
        raise ValueError(ERROR_MESSAGES["invalid_email"])
    
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

    # Check if the username already exists
    existing_user_by_username = db.query(User).filter_by(username=user_data.username).first()
    if existing_user_by_username:
        raise ValueError(ERROR_MESSAGES["username_exists"])
    
    # Create a new user object
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        country_code=user_data.country_code,
        phone_number=user_data.phone_number,
        role="user",  # Default role, can be changed if needed
    )
    
    # Set the user's password using the method from the User model
    try:
        new_user.set_password(user_data.password)
    except Exception as e:
        raise ValueError(f"Password error: {str(e)}")

    db.add(new_user)

    try:
        # Commit the transaction to add the new user to the database
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()  # Rollback the transaction in case of error
        # Check for specific errors related to unique fields
        if "email" in str(e):
            raise ValueError(ERROR_MESSAGES["email_exists"])
        elif "username" in str(e):
            raise ValueError(ERROR_MESSAGES["username_exists"])
        else:
            raise ValueError("Database error occurred while creating user.")

    # Generate tokens using the method from the User model
    try:
        access_token = new_user.generate_access_token()
        refresh_token = new_user.generate_refresh_token(db)
    except Exception as e:
        # Handle any token generation errors
        raise ValueError(f"Token generation error: {str(e)}")

    return {
        "user": new_user,
        "access_token": access_token,
        "refresh_token": refresh_token
    }
# *********** ========== End ========== ***********