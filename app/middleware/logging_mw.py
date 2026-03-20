import time
import logging
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

log = structlog.get_logger()


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Record start time
        start_time = time.monotonic()

        # Process the request
        response = await call_next(request)

        # Calculate duration
        duration_ms = round((time.monotonic() - start_time) * 1000, 2)

        # Log every request as structured JSON
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            client=request.client.host if request.client else "unknown",
        )

        return response
    