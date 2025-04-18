# src/auth/constants.py

# Regular Expressions for Validation
# Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.
PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"

# Username can only contain lowercase letters, numbers, underscores, and hyphens.
USERNAME_REGEX = r"^[a-z0-9_.-]+$"

# email regex
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

# Role choices for user permissions
ROLE_CHOICES = (
    "user",      # Regular user with standard permissions
    "admin",     # Administrator with elevated permissions
    "editor",    # User with permissions to edit content
    "moderator",  # User with permissions to moderate content
    "superuser"  # User with all permissions
)

# Constant for user ID reference
USER_ID_COLUMN = "users.id"  # Define a constant for the user ID column

# Error messages for user feedback
ERROR_MESSAGES = {
    "passwords_do_not_match": "Passwords do not match.",  # Error when passwords entered do not match
    "invalid_password": "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",  # Error for invalid password format
    "invalid_username": "Username must only contain lowercase letters, numbers, underscores, hyphens, or dots.",  # Error for invalid username format
    "invalid_role": "Invalid role. Allowed roles are: user and moderator",  # Error for invalid role
    "email_exists": "A user with this email already exists.",  # Error when email is already registered
    "phone_number_exists": "A user with this phone number already exists.",  # Error when phone number is already registered
    "username_exists": "A user with this username already exists.",  # Error when username is already taken
    "email_required": "Email is required.",  # Error for missing email
    "full_name_required": "Full name is required.",  # Error for missing full name
    "password_required": "Password is required.",  # Error for missing password
    "invalid_phone_number": "Invalid phone number format.",  # Error for invalid phone number
    "current_password_required": "Current password is required.",  # Error for missing current password
    "new_password_required": "New password is required.",  # Error for missing new password
    "confirm_password_required": "Confirm password is required.",  # Error for missing confirm password
    "token_required": "Token is required.",  # Error for missing token
    "invalid_data_format": "Invalid data format.",  # Error for invalid data format (e.g., schema validation errors)
    "unexpected_error": "An unexpected error occurred.",  # Error for unexpected server errors
    "incorrect_current_password": "The current password you entered is incorrect. Please try again.",  # Error for incorrect current password
    "new_password_same_as_old": "The new password cannot be the same as the old password. Please choose a different password.",  # Error for new password being the same as the old password
    "passwords_not_same": "Passwords do not match. Please ensure both passwords are identical.",  # Error when passwords entered do not match
    "user_not_found": "User not found.",  # Error when user is not found
}