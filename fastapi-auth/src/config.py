# src/config.py

import os

# *********** ========== Database Configuration ========== ***********
# Set the DATABASE_URL environment variable, defaulting to SQLite for testing
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")

# *********** ========== Application Settings ========== ***********
class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "FastAPI Project")  # Default project name
    VERSION: str = os.getenv("VERSION", "1.0.0")  # Default version
    PORT: int = int(os.getenv("PORT", 8000))  # Default port
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "*").split(",")  # Default to all origins
    ALLOWED_METHODS: list = os.getenv("ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS").split(",")  # Default methods
    ALLOWED_HEADERS: list = os.getenv("ALLOWED_HEADERS", "Content-Type,Authorization").split(",")  # Default headers

# Instantiate settings
settings = Settings()