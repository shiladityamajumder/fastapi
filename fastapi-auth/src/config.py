# src/config.py

import os
from dotenv import load_dotenv
from pydantic import EmailStr

# Load environment variables
load_dotenv()
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

    # Email settings
    SMTP_HOST: str = os.getenv("SMTP_HOST")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD")
    SMTP_FROM_EMAIL: EmailStr = os.getenv("SMTP_FROM_EMAIL")
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", PROJECT_NAME)
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", True)
    SMTP_USE_SSL: bool = os.getenv("SMTP_USE_SSL", False)

# Instantiate settings
settings = Settings()