# src/auth/service.py

# Standard library imports
import re
from datetime import datetime, timedelta, timezone

# Third-party library imports
from pydantic import ValidationError
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, Depends

# Local application imports
from .models import User, Token
from .schemas import UserCreateSchema, UserLoginSchema, LogoutRequestSchema, LogoutRequestSchema, LogoutResponseData, LogoutResponseWrapper
from .constants import ERROR_MESSAGES  # Importing error messages for user feedback
from .utils import get_current_user


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


# *********** ========== User Login Service ========== ***********
def authenticate_user(db: Session, login_data: UserLoginSchema):
    """
    Authenticate a user based on their email and password using the UserLoginSchema.

    Args:
        db (Session): The database session.
        login_data (UserLoginSchema): The login data containing email and password.

    Raises:
        ValueError: If the user is not found or the password is incorrect.

    Returns:
        dict: A dictionary containing the authenticated user and their access and refresh tokens.
    """

    # Validate the login data using UserLoginSchema
    try:
        validated_data = login_data.model_dump()  # Convert schema to dictionary
    except ValidationError as e:
        raise ValueError(f"Invalid login data: {str(e)}")

    # Extract email and password from validated data
    email = validated_data["email"]
    password = validated_data["password"]

    # Find the user by email
    user = db.query(User).filter_by(email=email).first()

    if not user:
        raise ValueError(ERROR_MESSAGES["user_not_found"])

    # Check if the password is correct
    if not user.verify_password(password):
        raise ValueError(ERROR_MESSAGES["incorrect_password"])

    # Generate new tokens for the user
    try:
        access_token = user.generate_access_token()
        refresh_token = user.generate_refresh_token(db)
    except Exception as e:
        # Handle any token generation errors
        raise ValueError(f"Token generation error: {str(e)}")

    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": refresh_token
    }
# *********** ========== End ========== ***********


# *********** ========== User Logout Service ========== ***********
def logout_user(db: Session, logout_data: LogoutRequestSchema, authorization: str):
    """
    Logs out a user by blacklisting their refresh token and invalidating the access token.

    Args:
        db (Session): The database session.
        logout_data (LogoutRequestSchema): The logout data containing the refresh token.
        authorization (str): The Bearer token from the request headers.

    Raises:
        ValueError: If the access token is invalid or the refresh token is not found.

    Returns:
        LogoutResponseWrapper: The response object with status and message.
    """
    # Validate the logout data using LogoutRequestSchema
    try:
        validated_data = logout_data.model_dump()  # Convert schema to dictionary
    except ValidationError as e:
        raise ValueError(f"Invalid logout data: {str(e)}")
    
    # Extract refresh token from validated data
    refresh_token = validated_data["refresh_token"]

    # Step 1: Validate the access token and extract the user ID
    try:
        current_user = get_current_user(authorization, db)
        user_id = current_user["user_id"]
    except HTTPException as e:
        raise ValueError(f"Invalid access token: {str(e.detail)}")

    # Step 2: Verify the refresh token and ensure it belongs to the user
    refresh_token_entry = db.query(Token).filter(
        Token.token == refresh_token,
        Token.user_id == user_id,
        Token.token_type == "refresh",
        Token.is_blacklisted == False
    ).first()

    if not refresh_token_entry:
        raise ValueError("Refresh token not found or already blacklisted")

    # Step 3: Blacklist the refresh token
    refresh_token_entry.is_blacklisted = True
    refresh_token_entry.is_active = False
    refresh_token_entry.last_modified_at = datetime.now(timezone.utc)
    db.commit()

    # Step 4: Return the success response
    response_data = LogoutResponseData(status="success", code=200)
    return LogoutResponseWrapper(
        data=response_data,
        message="User logged out successfully",
        status=True
    )
# *********** ========== End ========== ***********