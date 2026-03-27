import logging
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)

def rate_limit_error_handler(request: Request, exc: RateLimitExceeded):
    logger.warning(f"Rate limit exceeded for {get_remote_address(request)}")
    return JSONResponse(
        status_code=429,
        content={
            "error": "Too many requests. Please try again later.",
            "code": "RATE_LIMIT_EXCEEDED"
        }
    )