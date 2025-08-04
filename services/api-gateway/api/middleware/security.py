"""Security middleware for enhanced protection"""
import time
import uuid
from typing import Callable
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import structlog
import bleach

logger = structlog.get_logger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

class SecurityMiddleware:
    """Custom security middleware for request validation and sanitization"""
    
    def __init__(self, app, allowed_hosts: list = None, max_request_size: int = 10 * 1024 * 1024):
        self.app = app
        self.allowed_hosts = allowed_hosts or ["*"]
        self.max_request_size = max_request_size
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Add request ID for tracing
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Validate host header
        if not self._validate_host(request):
            response = JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Invalid host header"}
            )
            await response(scope, receive, send)
            return
        
        # Check request size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_request_size:
            response = JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": "Request too large"}
            )
            await response(scope, receive, send)
            return
        
        # Add security headers
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                
                # Security headers
                security_headers = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"x-xss-protection": b"1; mode=block",
                    b"referrer-policy": b"strict-origin-when-cross-origin",
                    b"content-security-policy": b"default-src 'self'",
                    b"x-request-id": request_id.encode(),
                }
                
                for key, value in security_headers.items():
                    headers[key] = value
                
                message["headers"] = [(k, v) for k, v in headers.items()]
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)
    
    def _validate_host(self, request: Request) -> bool:
        """Validate the host header"""
        if "*" in self.allowed_hosts:
            return True
        
        host = request.headers.get("host", "").lower()
        return any(allowed_host.lower() in host for allowed_host in self.allowed_hosts)


class RequestValidationMiddleware:
    """Middleware for input validation and sanitization"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Log request
        logger.info(
            "Incoming request",
            method=request.method,
            url=str(request.url),
            user_agent=request.headers.get("user-agent"),
            request_id=getattr(request.state, "request_id", None)
        )
        
        start_time = time.time()
        
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                process_time = time.time() - start_time
                
                # Log response
                logger.info(
                    "Request completed",
                    status_code=message["status"],
                    process_time=process_time,
                    request_id=getattr(request.state, "request_id", None)
                )
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)


def sanitize_input(data: str) -> str:
    """Sanitize input data to prevent XSS attacks"""
    if not isinstance(data, str):
        return data
    
    # Remove potentially harmful HTML/JavaScript
    return bleach.clean(
        data,
        tags=[],  # No HTML tags allowed
        attributes={},  # No attributes allowed
        strip=True
    )


def validate_json_input(data: dict) -> dict:
    """Validate and sanitize JSON input"""
    if not isinstance(data, dict):
        return data
    
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_input(value)
        elif isinstance(value, dict):
            sanitized[key] = validate_json_input(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_input(item) if isinstance(item, str) 
                else validate_json_input(item) if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            sanitized[key] = value
    
    return sanitized


# Rate limit exception handler
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Custom rate limit exceeded handler"""
    logger.warning(
        "Rate limit exceeded",
        client_ip=get_remote_address(request),
        request_id=getattr(request.state, "request_id", None)
    )
    
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Rate limit exceeded. Please try again later.",
            "retry_after": exc.retry_after
        }
    )
