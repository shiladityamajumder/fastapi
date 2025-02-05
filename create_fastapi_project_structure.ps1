# Define the project name
$projectName = "fastapi-auth"

# Create the main project directory
New-Item -ItemType Directory -Path $projectName

# Create the alembic directory
New-Item -ItemType Directory -Path "$projectName\alembic"

# Create the src directory and subdirectories
New-Item -ItemType Directory -Path "$projectName\src"
New-Item -ItemType Directory -Path "$projectName\src\auth"
New-Item -ItemType Directory -Path "$projectName\src\api"      # Replacing aws with api
New-Item -ItemType Directory -Path "$projectName\src\analytics" # Replacing posts with analytics

# Create files in the auth directory
New-Item -ItemType File -Path "$projectName\src\auth\router.py"
New-Item -ItemType File -Path "$projectName\src\auth\schemas.py"
New-Item -ItemType File -Path "$projectName\src\auth\models.py"
New-Item -ItemType File -Path "$projectName\src\auth\dependencies.py"
New-Item -ItemType File -Path "$projectName\src\auth\config.py"
New-Item -ItemType File -Path "$projectName\src\auth\constants.py"
New-Item -ItemType File -Path "$projectName\src\auth\exceptions.py"
New-Item -ItemType File -Path "$projectName\src\auth\service.py"
New-Item -ItemType File -Path "$projectName\src\auth\utils.py"
New-Item -ItemType File -Path "$projectName\src\auth\__init__.py"  # Add __init__.py

# Create files in the api directory
New-Item -ItemType File -Path "$projectName\src\api\router.py"
New-Item -ItemType File -Path "$projectName\src\api\schemas.py"
New-Item -ItemType File -Path "$projectName\src\api\models.py"
New-Item -ItemType File -Path "$projectName\src\api\dependencies.py"
New-Item -ItemType File -Path "$projectName\src\api\config.py"
New-Item -ItemType File -Path "$projectName\src\api\constants.py"
New-Item -ItemType File -Path "$projectName\src\api\exceptions.py"
New-Item -ItemType File -Path "$projectName\src\api\service.py"
New-Item -ItemType File -Path "$projectName\src\api\utils.py"
New-Item -ItemType File -Path "$projectName\src\api\__init__.py"  # Add __init__.py

# Create files in the analytics directory
New-Item -ItemType File -Path "$projectName\src\analytics\router.py"
New-Item -ItemType File -Path "$projectName\src\analytics\schemas.py"
New-Item -ItemType File -Path "$projectName\src\analytics\models.py"
New-Item -ItemType File -Path "$projectName\src\analytics\dependencies.py"
New-Item -ItemType File -Path "$projectName\src\analytics\config.py"
New-Item -ItemType File -Path "$projectName\src\analytics\constants.py"
New-Item -ItemType File -Path "$projectName\src\analytics\exceptions.py"
New-Item -ItemType File -Path "$projectName\src\analytics\service.py"
New-Item -ItemType File -Path "$projectName\src\analytics\utils.py"
New-Item -ItemType File -Path "$projectName\src\analytics\__init__.py"  # Add __init__.py

# Create global files in the src directory
New-Item -ItemType File -Path "$projectName\src\config.py"
New-Item -ItemType File -Path "$projectName\src\models.py"
New-Item -ItemType File -Path "$projectName\src\exceptions.py"
New-Item -ItemType File -Path "$projectName\src\pagination.py"
New-Item -ItemType File -Path "$projectName\src\database.py"
New-Item -ItemType File -Path "$projectName\src\main.py"
New-Item -ItemType File -Path "$projectName\src\__init__.py"  # Add __init__.py

# Create the tests directory and subdirectories
New-Item -ItemType Directory -Path "$projectName\tests"
New-Item -ItemType Directory -Path "$projectName\tests\auth"
New-Item -ItemType Directory -Path "$projectName\tests\api"
New-Item -ItemType Directory -Path "$projectName\tests\analytics"

# Create __init__.py files in the tests directories
New-Item -ItemType File -Path "$projectName\tests\auth\__init__.py"
New-Item -ItemType File -Path "$projectName\tests\api\__init__.py"
New-Item -ItemType File -Path "$projectName\tests\analytics\__init__.py"

# Create the templates directory
New-Item -ItemType Directory -Path "$projectName\templates"
New-Item -ItemType File -Path "$projectName\templates\index.html"

# Create the requirements directory and files
New-Item -ItemType Directory -Path "$projectName\requirements"
New-Item -ItemType File -Path "$projectName\requirements\base.txt"
New-Item -ItemType File -Path "$projectName\requirements\dev.txt"
New-Item -ItemType File -Path "$projectName\requirements\prod.txt"

# Create other necessary files
New-Item -ItemType File -Path "$projectName\.env"
New-Item -ItemType File -Path "$projectName\.gitignore"
New-Item -ItemType File -Path "$projectName\logging.ini"
New-Item -ItemType File -Path "$projectName\alembic.ini"