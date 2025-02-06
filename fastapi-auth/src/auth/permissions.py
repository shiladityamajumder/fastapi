# src/auth/permissions.py

from fastapi import HTTPException, status, Depends
from .models import User
from .utils import get_current_user


# *********** ========== Permission Classes ========== ***********
def is_authenticated(user: User = Depends(get_current_user)) -> User:
    """
    Permission: Ensures the user is authenticated.

    Args:
        user (User): The authenticated user.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: If the user is not authenticated.
    """
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not active",
        )
    return user


def is_admin(user: User = Depends(get_current_user)) -> User:
    """
    Permission: Ensures the user is an admin.

    Args:
        user (User): The authenticated user.

    Returns:
        User: The authenticated admin user.

    Raises:
        HTTPException: If the user is not an admin.
    """
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not an admin",
        )
    return user


# ? pass the specific role in routers
def has_role(role: str):
    """
    Permission: Ensures the user has a specific role.

    Args:
        role (str): The required role.

    Returns:
        User: The authenticated user with the required role.

    Raises:
        HTTPException: If the user does not have the required role.
    """
    def role_checker(user: User = Depends(get_current_user)):
        if user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User does not have the required role: {role}",
            )
        return user
    return role_checker
# *********** ========== End of Permission Classes ========== ***********