"""JSON log formatter for the ``security`` logger.

Emits one JSON object per line. Only whitelisted, non-sensitive fields are
written; see ``audit.events.log_event`` for the call sites.
"""
import json
import logging


class JSONFormatter(logging.Formatter):
    # Standard LogRecord attributes we never want echoed back into the payload.
    _RESERVED = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any structured extras attached via logger.info(..., extra={...}).
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload.setdefault(key, value)
        return json.dumps(payload, default=str)
