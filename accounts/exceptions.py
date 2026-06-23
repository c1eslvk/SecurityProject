"""DRF exception handling that avoids leaking internals to clients.

In production (DEBUG off) any unhandled server error is returned as a generic
500 body with no stack trace or exception message. DRF's standard 4xx handling
is preserved so clients still get actionable validation/permission errors.
"""
import logging

from django.conf import settings
from rest_framework.response import Response
from rest_framework.views import exception_handler

_logger = logging.getLogger("security")


def safe_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is not None:
        return response

    # Unhandled, non-DRF exception => would otherwise be a 500 with a traceback.
    _logger.error("unhandled_exception", extra={"event": "unhandled_exception"})
    if settings.DEBUG:
        return None  # let Django render the debug page locally
    return Response({"detail": "Internal server error."}, status=500)
