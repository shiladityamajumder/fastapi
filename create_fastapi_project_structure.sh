#!/bin/bash

# Define the project name
project_name="fastapi-project"

# Create the main project directory
mkdir -p "$project_name/alembic"

# Create the src directory and subdirectories
mkdir -p "$project_name/src/auth"
mkdir -p "$project_name/src/api"
mkdir -p "$project_name/src/analytics"

# Create files in the auth directory
touch "$project_name/src/auth/router.py"
touch "$project_name/src/auth/schemas.py"
touch "$project_name/src/auth/models.py"
touch "$project_name/src/auth/dependencies.py"
touch "$project_name/src/auth/config.py"
touch "$project_name/src/auth/constants.py"
touch "$project_name/src/auth/exceptions.py"
touch "$project_name/src/auth/service.py"
touch "$project_name/src/auth/utils.py"

# Create files in the api directory
touch "$project_name/src/api/router.py"
touch "$project_name/src/api/schemas.py"
touch "$project_name/src/api/models.py"
touch "$project_name/src/api/dependencies.py"
touch "$project_name/src/api/config.py"
touch "$project_name/src/api/constants.py"
touch "$project_name/src/api/exceptions.py"
touch "$project_name/src/api/service.py"
touch "$project_name/src/api/utils.py"

# Create files in the analytics directory
touch "$project_name/src/analytics/router.py"
touch "$project_name/src/analytics/schemas.py"
touch "$project_name/src/analytics/models.py"
touch "$project_name/src/analytics/dependencies.py"
touch "$project_name/src/analytics/config.py"
touch "$project_name/src/analytics/constants.py"
touch "$project_name/src/analytics/exceptions.py"
touch "$project_name/src/analytics/service.py"
touch "$project_name/src/analytics/utils.py"

# Create global files in the src directory
touch "$project_name/src/config.py"
touch "$project_name/src/models.py"
touch "$project_name/src/exceptions.py"
touch "$project_name/src/pagination.py"
touch "$project_name/src/database.py"
touch "$project_name/src/main.py"

# Create the tests directory and subdirectories
mkdir -p "$project_name/tests/auth"
mkdir -p "$project_name/tests/api"
mkdir -p "$project_name/tests/analytics"

# Create the templates directory
mkdir -p "$project_name/templates"
touch "$project_name/templates/index.html"

# Create the requirements directory and files
mkdir -p "$project_name/requirements"
touch "$project_name/requirements/base.txt"
touch "$project_name/requirements/dev.txt"
touch "$project_name/requirements/prod.txt"

# Create other necessary files
touch "$project_name/.env"
touch "$project_name/.gitignore"
touch "$project_name/logging.ini"
touch "$project_name/alembic.ini"

echo "Project structure created successfully!"