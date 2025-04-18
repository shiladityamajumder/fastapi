# src/main.py

# Standard library imports
import logging
import uvicorn
from contextlib import asynccontextmanager

# Third-party library imports
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

# Local application imports
from src.auth.router import router as auth_router  # Importing the authentication router
from src.config import settings  # Importing application settings


# *********** ========== Configure Logging ========== ***********
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Saves logs to a file
        logging.StreamHandler()  # Prints logs to the console
    ]
)
logger = logging.getLogger(__name__)


# *********** ========== Lifespan Event ========== ***********
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting FastAPI application...")
    yield
    logger.info("Shutting down FastAPI application...")


# *********** ========== Create FastAPI Instance ========== ***********
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="A robust FastAPI backend",
    lifespan=lifespan,
)

# *********** ========== Initialize Rate Limiter ========== ***********
limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379")
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# *********** ========== Middleware Configuration ========== ***********
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)


# *********** ========== Include Routers ========== ***********
app.include_router(auth_router)


# *********** ========== Custom Exception Handler ========== ***********
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = [
        {
            "field": error["loc"][-1],  # Extracts the field name
            "message": error["msg"],
            "type": error["type"]
        }
        for error in exc.errors()
    ]

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "data": {
                "details": errors,
                "status": "error",
                "code": status.HTTP_422_UNPROCESSABLE_ENTITY
            },
            "message": "Validation failed",
            "status": False
        },
    )


# *********** ========== Root Route ========== ***********
@app.get("/", tags=["General"])
async def read_root():
    return {"message": "Welcome to the FastAPI service!"}


# *********** ========== Health Check Route ========== ***********
@app.get("/health", tags=["Monitoring"])
async def health_check():
    return {"status": "ok"}


# *********** ========== Run the Application ========== ***********
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=settings.PORT, reload=True)
# *********** ========== End ========== ***********