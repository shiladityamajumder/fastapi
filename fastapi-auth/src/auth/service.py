# src/auth/service.py

# Standard library imports
import re
from datetime import datetime, timedelta, timezone

# Third-party library imports
from pydantic import ValidationError
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, Depends, Request

# Local application imports
from .models import User, Token, Session, PasswordReset
from .schemas import (
    UserCreateSchema, UserResponseSchema, AuthTokensSchema, UserAuthResponseSchema, AuthResponseWrapper, 
    UserLoginSchema, ProfileUpdateRequestSchema, UserProfileResponseData, UserProfileResponseWrapper, 
    ChangePasswordRequestSchema, ChangePasswordResponseData, ChangePasswordResponseWrapper, 
    PasswordResetRequestSchema, PasswordResetRequestResponseData, PasswordResetRequestResponseWrapper, 
    ResetPasswordWithTokenRequestSchema, ResetPasswordResponseData, ResetPasswordResponseWrapper, 
    LogoutRequestSchema, LogoutResponseData, LogoutResponseWrapper, 
    RefreshTokenRequestSchema, RefreshTokenRegenerateSchema,
    ErrorDetails, ErrorResponseWrapper, 
    SessionCreateSchema, SessionResponseSchema, ListSessionsResponseSchema, 
    RevokeSessionRequestSchema, RevokeSessionResponseSchema, SessionWrapper, 
)
from .constants import ERROR_MESSAGES  # Importing error messages for user feedback
from .utils import get_current_user
from .emails import send_registration_email, send_password_reset_email


# *********** ========== User Registartion Service ========== ***********
def create_user(db: Session, creator_user: User, user_data: UserCreateSchema):
    """
    Create a new user in the database.

    Args:
        db (Session): The database session.
        creator_user (User): The admin/moderator creating the new user.
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
        role=user_data.role or "user",  # Use provided role or default to "user"
        created_by=creator_user.id if hasattr(User, "created_by") else None  # Optional tracking
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


    # Create a new session for the user
    new_session = Session(
        user_id=new_user.id,
        device_info="Admin Device",  # You can customize this as needed
        ip_address="0.0.0.0"  # Replace with actual IP address if available
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    # Generate tokens using the method from the User model
    try:
        access_token = new_user.generate_access_token()
        refresh_token = new_user.generate_refresh_token(db, new_session.id)
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
def authenticate_user(request: Request, login_data: UserLoginSchema, db: Session):
    """
    Authenticate a user based on their email and password using the UserLoginSchema.

    Args:
        request (Request): The HTTP request object.
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

    # Check for an existing active session for the same user and device
    existing_session = db.query(Session).filter(
        Session.user_id == user.id,
        Session.device_info == request.headers.get("User-Agent", "Unknown"),
        Session.is_active == True
    ).first()

    # If an existing session is found, deactivate it
    if existing_session:
        db.delete(existing_session)  # Delete the previous session
        db.commit()  # Commit the changes to the database

    # Create a new session for the user
    try:
        new_session = Session(
            user_id=user.id,
            device_info=request.headers.get("User-Agent", "Unknown"),  # Get device info from request
            ip_address=request.client.host  # Get IP address from request
        )
        db.add(new_session)
        db.commit()
    except Exception as e:
        # Handle session creation errors
        raise ValueError(f"Session creation error: {str(e)}")
    
    # Generate new tokens for the user
    try:
        access_token = user.generate_access_token()
        refresh_token = user.generate_refresh_token(db, new_session.id)  # Pass the new session ID
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
        session_id=new_session.id,
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

    # Check the most recent password reset request for this user
    latest_reset_entry = (
        db.query(PasswordReset)
        .filter(PasswordReset.user_id == user.id)
        .order_by(PasswordReset.created_at.desc())
        .first()
    )

    if latest_reset_entry:
        # Ensure created_at is not None
        if latest_reset_entry.created_at is None:
            raise ValueError("Invalid password reset record: missing created_at timestamp.")

        # Ensure created_at has timezone info
        last_request_time = latest_reset_entry.created_at.replace(tzinfo=timezone.utc) if latest_reset_entry.created_at.tzinfo is None else latest_reset_entry.created_at
        time_since_last_request = datetime.now(timezone.utc) - last_request_time
        
        if time_since_last_request < timedelta(minutes=2):
            raise ValueError("Please wait at least 2 minutes before requesting a new OTP.")

    otp = PasswordReset.generate_otp()
    expiry_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    password_reset_entry = PasswordReset(
        user_id=user.id,
        otp_code=otp,
        expires_at=expiry_time,
        is_used=False,
        is_active=True,
        created_at=datetime.now(timezone.utc)
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


# *********** ========== Get User Profile Service ========== ***********
def get_user_profile_service(db: Session, user: User):
    """
    Fetch the authenticated user's profile details.

    Args:
        db (Session): Database session.
        user (User): The authenticated user.

    Returns:
        UserProfileResponseWrapper: The user's profile details.
    """

    if not user:
        raise ValueError(ERROR_MESSAGES["user_not_found"])

    user_data = UserProfileResponseData(
        user=user,
        status="success",
        code=200
    )

    return UserProfileResponseWrapper(
        data=user_data,
        message="User profile retrieved successfully",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== Update User Profile Service ========== ***********
def update_user_profile_service(db: Session, user: User, update_data: ProfileUpdateRequestSchema):
    """
    Update the authenticated user's profile information.

    Args:
        db (Session): Database session.
        user (User): The authenticated user.
        update_data (ProfileUpdateRequestSchema): The updated user data.

    Returns:
        UserProfileResponseWrapper: The updated user's profile details.
    """

    # Validate the input data
    try:
        validated_data = update_data.model_dump(exclude_unset=True)  # Convert schema to dictionary
    except Exception as e:
        raise ValueError(f"Invalid profile update data: {str(e)}")

    if not validated_data:
        raise ValueError(ERROR_MESSAGES["no_fields_provided"])

    # Update user attributes
    for key, value in validated_data.items():
        setattr(user, key, value)

    user.updated_at = datetime.now(timezone.utc)

    try:
        db.commit()
        db.refresh(user)  # Refresh the user instance to get updated data
    except Exception:
        db.rollback()
        raise ValueError(ERROR_MESSAGES["db_update_failed"])

    return UserProfileResponseWrapper(
        data=UserProfileResponseData(
            user=user,
            status="success",
            code=200
        ),
        message="Profile updated successfully",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== Refresh Access Token Service ========== ***********
def refresh_access_token(db: Session, refresh_data: RefreshTokenRequestSchema):
    """
    Generate a new access token using a valid refresh token.

    Args:
        db (Session): The database session.
        refresh_data (RefreshTokenRequestSchema): The request data containing the refresh token.

    Raises:
        ValueError: If the refresh token is invalid or expired.

    Returns:
        AuthResponseWrapper: Response object with user data and new access token.
    """

    # Verify the refresh token
    refresh_token_payload = User.verify_refresh_token(refresh_data.refresh_token, db)
    if not refresh_token_payload:
        raise ValueError("Invalid or expired refresh token.")

    # Retrieve user from the database
    user = db.query(User).filter_by(id=refresh_token_payload["user_id"]).first()
    if not user:
        raise ValueError("User not found.")

    # Generate a new access token
    access_token = user.generate_access_token()

    # Construct response data
    response_data = UserAuthResponseSchema(
        tokens=AuthTokensSchema(
            access=access_token,
            refresh=refresh_data.refresh_token  # Reusing the provided refresh token
        ),
        user=UserResponseSchema.model_validate(user),
        status="success",
        code=200
    )

    return AuthResponseWrapper(
        data=response_data,
        message="Access token refreshed successfully.",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== Regenerate Access Token Service ========== ***********
def regenerate_access_token(db: Session, regenerate_data: RefreshTokenRegenerateSchema):
    """
    Regenerate a new access token using a valid refresh token and token regeneration code.

    Args:
        db (Session): The database session.
        regenerate_data (RefreshTokenRegenerateSchema): The request data containing refresh token and regeneration code.

    Raises:
        ValueError: If the refresh token is invalid, the user is not found, or the regeneration code is incorrect.

    Returns:
        AuthResponseWrapper: Response object with user data and new access token.
    """

    # Verify the refresh token
    refresh_token_payload = User.verify_refresh_token(regenerate_data.refresh_token, db)
    if not refresh_token_payload:
        raise ValueError("Invalid or expired refresh token.")

    # Retrieve user from the database
    user = db.query(User).filter_by(id=refresh_token_payload["user_id"]).first()
    if not user:
        raise ValueError("User not found.")

    # Validate the token regeneration code
    if user.token_regeneration_code != regenerate_data.token_regeneration_code:
        raise ValueError("Invalid token regeneration code.")

    # Generate a new access token
    access_token = user.generate_access_token()

    # Construct response data
    response_data = UserAuthResponseSchema(
        tokens=AuthTokensSchema(
            access=access_token,
            refresh=regenerate_data.refresh_token  # Reusing the provided refresh token
        ),
        user=UserResponseSchema.model_validate(user),
        status="success",
        code=200
    )

    return AuthResponseWrapper(
        data=response_data,
        message="Access token regenerated successfully.",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== List Active Sessions Service ========== ***********
def list_active_sessions(db: Session, user_id: str):
    """
    Retrieve all active sessions for a user.

    Args:
        db (Session): The database session.
        user_id (str): The ID of the user.

    Returns:
        ListSessionsResponseSchema: The response object with active sessions.
    """

    # Query active sessions for the user
    sessions = db.query(Session).filter(
        Session.user_id == user_id,
        Session.is_active == True
    ).all()

    # Convert sessions to SessionResponseSchema
    session_responses = [SessionResponseSchema.model_validate(session) for session in sessions]

    return ListSessionsResponseSchema(
        sessions=session_responses,
        message="Active sessions retrieved successfully",
        status=True
    )
# *********** ========== End ========== ***********


# *********** ========== Revoke Session Service ========== ***********
def revoke_session(db: Session, session_id: str, user_id: str):
    """
    Revoke a specific session for a user.

    Args:
        db (Session): The database session.
        session_id (str): The ID of the session to revoke.
        user_id (str): The ID of the user.

    Returns:
        RevokeSessionResponseSchema: The response object with a success message.

    Raises:
        ValueError: If the session is not found or does not belong to the user.
    """

    # Find the session
    session = db.query(Session).filter(
        Session.id == session_id,
        Session.user_id == user_id
    ).first()

    if not session:
        raise ValueError("Session not found or does not belong to the user.")

    # Revoke the session
    session.is_active = False
    db.commit()

    # Invalidate the token associated with this session
    token = db.query(Token).filter(
        Token.session_id == session_id,
        Token.user_id == user_id
    ).first()

    if token:
        token.is_blacklisted = True
        db.commit()

    return RevokeSessionResponseSchema(
        message="Session and associated token revoked successfully",
        status=True
    )
# *********** ========== End ========== ***********