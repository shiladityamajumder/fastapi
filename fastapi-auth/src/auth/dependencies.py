# src/auth/dependencies.py

# Standard library imports
from typing import Generator

# Third-party library imports
from sqlalchemy.orm import Session
from fastapi import Depends

# Local application imports
from src.database import SessionLocal  # Importing the database session factory


def get_db() -> Generator[Session, None, None]:
    """
    Dependency that provides a database session.

    Yields:
        Session: A SQLAlchemy database session.
    """
    db = SessionLocal()  # Create a new database session
    try:
        yield db  # Yield the session to the caller
    finally:
        db.close()  # Close the session when done
