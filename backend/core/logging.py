"""Structured JSON logging with redaction.

Logged fields: analysis_id, sample_id, event, timestamp, engine, status, error.
Never logged: file contents, archive passwords, full secrets, tokens.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

_REDACT_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)(\s*[=:]\s*)([^\s,;&\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), "eyJ[REDACTED-JWT]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED-PRIVATE-KEY]"),
]
_ALLOWED_EXTRA = ("analysis_id", "sample_id", "event", "engine", "status", "error", "duration_ms", "detail")
_FORBIDDEN_KEYS = {"password", "archive_password", "secret", "token", "content", "data"}


def redact(text: str) -> str:
    for pattern, repl in _REDACT_PATTERNS:
        text = pattern.sub(repl, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        for key in _ALLOWED_EXTRA:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = redact(str(value)) if isinstance(value, str) else value
        if record.exc_info:
            payload["error"] = redact(self.formatException(record.exc_info).splitlines()[-1])
        return json.dumps(payload, ensure_ascii=False, default=str)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for key in _FORBIDDEN_KEYS:
            if hasattr(record, key):
                setattr(record, key, "[REDACTED]")
        return True


_configured = False


def configure_logging(level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger("malx")
    root.setLevel(level)
    root.handlers = [handler]
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"malx.{name}")


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields) -> None:
    extra = {k: v for k, v in fields.items() if k in _ALLOWED_EXTRA}
    extra["event"] = event
    logger.log(level, event, extra=extra)
