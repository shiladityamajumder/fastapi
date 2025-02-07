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
from .models import User, Token, PasswordReset
from .schemas import (
    UserCreateSchema, UserResponseSchema, AuthTokensSchema, UserAuthResponseSchema, AuthResponseWrapper, 
    UserLoginSchema, ProfileUpdateRequestSchema, UserProfileResponseData, UserProfileResponseWrapper, 
    ChangePasswordRequestSchema, ChangePasswordResponseData, ChangePasswordResponseWrapper, 
    PasswordResetRequestSchema, PasswordResetRequestResponseData, PasswordResetRequestResponseWrapper, 
    ResetPasswordWithTokenRequestSchema, ResetPasswordResponseData, ResetPasswordResponseWrapper, 
    LogoutRequestSchema, LogoutResponseData, LogoutResponseWrapper, 
    ErrorDetails, ErrorResponseWrapper,
)
from .constants import ERROR_MESSAGES  # Importing error messages for user feedback
from .utils import get_current_user
from .emails import send_registration_email, send_password_reset_email


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
        AuthResponseWrapper: The response object with user data, tokens, and status.
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

    # Send the registration email asynchronously
    try:
        send_registration_email(user_email=new_user.email, user_name=new_user.full_name)
    except Exception as e:
        # Log the error instead of failing user registration
        print(f"Failed to send registration email: {str(e)}")  # Replace with proper logging

    # Construct the response data
    response_data = UserAuthResponseSchema(
        tokens=AuthTokensSchema(
            access=access_token,
            refresh=refresh_token
        ),
        user=UserResponseSchema.model_validate(new_user),
        status="success",
        code=201
    )

    # Wrap the response data in the AuthResponseWrapper
    return AuthResponseWrapper(
        data=response_data,
        message="Registration successful",
        status=True
    )
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
        AuthResponseWrapper: The response object with user data, tokens, and status.
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

    # Construct the response
    response_data = UserAuthResponseSchema(
        tokens=AuthTokensSchema(
            access=access_token,
            refresh=refresh_token
        ),
        user=UserResponseSchema.model_validate(user),
        status="success",
        code=200
    )
    
    return AuthResponseWrapper(
        data=response_data,
        message="Login successful",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== User Logout Service ========== ***********
def logout_user(db: Session, user: User, logout_data: LogoutRequestSchema):
    """
    Logs out a user by blacklisting their refresh token and invalidating the access token.

    Args:
        db (Session): The database session.
        user (User): The authenticated user.
        logout_data (LogoutRequestSchema): The logout data containing the refresh token.

    Raises:
        ValueError: If the refresh token is not found or already blacklisted.

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

    # Step 1: Verify the refresh token and ensure it belongs to the user
    refresh_token_entry = db.query(Token).filter(
        Token.token == refresh_token,
        Token.user_id == user.id,  # Use the user ID from the authenticated user
        Token.token_type == "refresh",
        Token.is_blacklisted == False
    ).first()

    if not refresh_token_entry:
        raise ValueError("Refresh token not found or already blacklisted")

    # Step 2: Blacklist the refresh token
    refresh_token_entry.is_blacklisted = True
    refresh_token_entry.is_active = False
    refresh_token_entry.last_modified_at = datetime.now(timezone.utc)
    db.commit()

    # Step 3: Return the success response
    response_data = LogoutResponseData(status="success", code=200)
    return LogoutResponseWrapper(
        data=response_data,
        message="User logged out successfully",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== Change Password Service ========== ***********
def change_password_service(db: Session, user: User, change_password_data: ChangePasswordRequestSchema):
    """
    Handles the change password functionality for an authenticated user.

    Args:
        db (Session): The database session.
        user (User): The authenticated user.
        change_password_data (ChangePasswordRequestSchema): The change password request data.

    Raises:
        ValueError: If the current password is incorrect or the new password is the same as the old password.

    Returns:
        ChangePasswordResponseWrapper: The response object with status and message.
    """
    # Validate input data
    validated_data = change_password_data.model_dump()
    current_password = validated_data["current_password"]
    new_password = validated_data["new_password"]

    # Verify current password
    if not user.verify_password(current_password):
        raise ValueError(ERROR_MESSAGES["incorrect_current_password"])
    
    # Ensure the new password is different from the current password
    if current_password == new_password:
        raise ValueError(ERROR_MESSAGES["new_password_same_as_old"])
    
    # Update password
    user.set_password(new_password)
    user.last_modified_at = datetime.now(timezone.utc)
    db.commit()
    
    # Return success response
    response_data = ChangePasswordResponseData(status="success", code=200)
    return ChangePasswordResponseWrapper(
        data=response_data,
        message="Password changed successfully",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== Send Password Reset OTP Service ========== ***********
def send_password_reset_otp_service(db: Session, request_data: PasswordResetRequestSchema):
    user = db.query(User).filter(User.email == request_data.email).first()
    if not user:
        raise ValueError(ERROR_MESSAGES["user_not_found"])
    
    otp = PasswordReset.generate_otp()

    expiry_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    password_reset_entry = PasswordReset(
        user_id=user.id,
        otp_code=otp,
        expires_at=expiry_time,
        is_used=False,
        is_active=True
    )

    db.add(password_reset_entry)

    try:
        db.commit()
    except Exception:
        db.rollback()  # Rollback in case of error
        raise ValueError("Database error: Could not save OTP")

    
    send_password_reset_email(user_email=user.email, user_name=user.full_name, otp=otp)
    
    response_data = PasswordResetRequestResponseWrapper(
        data=PasswordResetRequestResponseData(email=user.email, status="success", code=200),
        message="OTP sent successfully",
        status=True
    )
    return response_data
# *********** ========== End ========== ***********


# *********** ========== Reset Password Service ========== ***********
def reset_password_service(db: Session, request_data: ResetPasswordWithTokenRequestSchema):
    user = db.query(User).filter(User.email == request_data.email).first()
    if not user:
        print(f"User not found for email: {request_data.email}")
        raise ValueError(ERROR_MESSAGES["user_not_found"])

    otp_entry = (
        db.query(PasswordReset)
        .filter(
            PasswordReset.user_id == user.id,
            PasswordReset.otp_code == request_data.otp,
            PasswordReset.is_active == True
        )
        .order_by(PasswordReset.expires_at.desc())  # Get latest OTP
        .first()
    )
    
    if not otp_entry or not otp_entry.is_valid(request_data.otp):
        print(f"OTP '{request_data.otp}' not found or inactive for user {request_data.email}!")
        raise ValueError("Invalid or expired OTP")
    
    user.set_password(request_data.new_password)
    user.last_modified_at = datetime.now(timezone.utc)
    otp_entry.is_used = True
    otp_entry.is_active = False
    
    db.commit()
    
    response_data = ResetPasswordResponseWrapper(
        data=ResetPasswordResponseData(status="success", code=200),
        message="Password reset successfully",
        status=True
    )
    return response_data
# *********** ========== End ========== ***********