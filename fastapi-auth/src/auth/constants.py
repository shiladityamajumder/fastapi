# src/auth/constants.py

# Regular Expressions for Validation
# Password must be at least 8 characters long and contain at least one letter and one number.
PASSWORD_REGEX = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$"

# Username can only contain letters, numbers, underscores, and hyphens.
USERNAME_REGEX = r"^[a-zA-Z0-9_.-]+$"

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
    "invalid_password": "Password must be at least 8 characters long, contain letters and numbers.",  # Error for invalid password format
    "invalid_username": "Username can only contain letters, numbers, underscores, or dots.",  # Error for invalid username format
    "email_exists": "A user with this email already exists.",  # Error when email is already registered
    "username_exists": "A user with this username already exists.",  # Error when username is already taken
}