from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from jose import JWTError
from logger import log_error

class TokenException(Exception):
    def __init__(self, message: str):
        self.message = message

async def token_exception_handler(request: Request, exc: TokenException):
    log_error(f"Token exception: {exc.message}", exc)
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": exc.message}
    )

async def jwt_exception_handler(request: Request, exc: JWTError):
    log_error("JWT validation error", exc)
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": "Invalid or expired token"}
    )

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    log_error(f"Validation error: {exc.errors()}", exc)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()}
    )

