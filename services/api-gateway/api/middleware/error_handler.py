"""Enhanced error handling middleware"""

import traceback
from typing import Union

import structlog
from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

logger = structlog.get_logger(__name__)


class ErrorHandlerMiddleware:
    """Middleware for centralized error handling"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        try:
            await self.app(scope, receive, send)
        except Exception as exc:
            response = await self._handle_exception(request, exc)
            await response(scope, receive, send)

    async def _handle_exception(self, request: Request, exc: Exception) -> JSONResponse:
        """Handle different types of exceptions"""
        request_id = getattr(request.state, "request_id", None)

        if isinstance(exc, HTTPException):
            return await self._handle_http_exception(request, exc, request_id)
        elif isinstance(exc, RequestValidationError):
            return await self._handle_validation_error(request, exc, request_id)
        elif isinstance(exc, ValidationError):
            return await self._handle_pydantic_validation_error(
                request, exc, request_id
            )
        else:
            return await self._handle_internal_error(request, exc, request_id)

    async def _handle_http_exception(
        self, request: Request, exc: HTTPException, request_id: str
    ) -> JSONResponse:
        """Handle HTTP exceptions"""
        logger.warning(
            "HTTP exception occurred",
            status_code=exc.status_code,
            detail=exc.detail,
            request_id=request_id,
            path=request.url.path,
            method=request.method,
        )

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTP_EXCEPTION",
                "detail": exc.detail,
                "request_id": request_id,
            },
        )

    async def _handle_validation_error(
        self, request: Request, exc: RequestValidationError, request_id: str
    ) -> JSONResponse:
        """Handle request validation errors"""
        errors = []
        for error in exc.errors():
            errors.append(
                {
                    "field": ".".join(str(x) for x in error["loc"]),
                    "message": error["msg"],
                    "type": error["type"],
                }
            )

        logger.warning(
            "Request validation error",
            errors=errors,
            request_id=request_id,
            path=request.url.path,
            method=request.method,
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "VALIDATION_ERROR",
                "detail": "Request validation failed",
                "errors": errors,
                "request_id": request_id,
            },
        )

    async def _handle_pydantic_validation_error(
        self, request: Request, exc: ValidationError, request_id: str
    ) -> JSONResponse:
        """Handle Pydantic validation errors"""
        errors = []
        for error in exc.errors():
            errors.append(
                {
                    "field": ".".join(str(x) for x in error["loc"]),
                    "message": error["msg"],
                    "type": error["type"],
                }
            )

        logger.warning(
            "Pydantic validation error",
            errors=errors,
            request_id=request_id,
            path=request.url.path,
            method=request.method,
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "VALIDATION_ERROR",
                "detail": "Data validation failed",
                "errors": errors,
                "request_id": request_id,
            },
        )

    async def _handle_internal_error(
        self, request: Request, exc: Exception, request_id: str
    ) -> JSONResponse:
        """Handle internal server errors"""
        error_traceback = traceback.format_exc()

        logger.error(
            "Internal server error",
            error_type=type(exc).__name__,
            error_message=str(exc),
            traceback=error_traceback,
            request_id=request_id,
            path=request.url.path,
            method=request.method,
        )

        # Don't expose internal error details in production
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "detail": "An internal server error occurred",
                "request_id": request_id,
            },
        )


# Custom exception classes
class BusinessLogicError(Exception):
    """Custom exception for business logic errors"""

    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


class DatabaseError(Exception):
    """Custom exception for database errors"""

    def __init__(self, message: str, operation: str = None):
        self.message = message
        self.operation = operation
        super().__init__(self.message)


class ExternalServiceError(Exception):
    """Custom exception for external service errors"""

    def __init__(self, message: str, service: str = None, status_code: int = None):
        self.message = message
        self.service = service
        self.status_code = status_code
        super().__init__(self.message)


# Exception handlers for custom exceptions
async def business_logic_error_handler(request: Request, exc: BusinessLogicError):
    """Handle business logic errors"""
    request_id = getattr(request.state, "request_id", None)

    logger.warning(
        "Business logic error",
        error_code=exc.error_code,
        message=exc.message,
        request_id=request_id,
    )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "BUSINESS_LOGIC_ERROR",
            "error_code": exc.error_code,
            "detail": exc.message,
            "request_id": request_id,
        },
    )


async def database_error_handler(request: Request, exc: DatabaseError):
    """Handle database errors"""
    request_id = getattr(request.state, "request_id", None)

    logger.error(
        "Database error",
        operation=exc.operation,
        message=exc.message,
        request_id=request_id,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "DATABASE_ERROR",
            "detail": "A database error occurred",
            "request_id": request_id,
        },
    )


async def external_service_error_handler(request: Request, exc: ExternalServiceError):
    """Handle external service errors"""
    request_id = getattr(request.state, "request_id", None)

    logger.error(
        "External service error",
        service=exc.service,
        status_code=exc.status_code,
        message=exc.message,
        request_id=request_id,
    )

    return JSONResponse(
        status_code=status.HTTP_502_BAD_GATEWAY,
        content={
            "error": "EXTERNAL_SERVICE_ERROR",
            "detail": f"External service ({exc.service}) is unavailable",
            "request_id": request_id,
        },
    )
