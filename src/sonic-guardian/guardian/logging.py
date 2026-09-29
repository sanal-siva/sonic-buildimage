"""Structured JSON logging utilities for SONiC Guardian"""

import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class StructuredJsonFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "user_data"):
            log_entry.update(record.user_data)

        return json.dumps(log_entry)


def setup_logging(name: str, level: str = "INFO") -> logging.Logger:
    """Configure structured logging for a component

    Args:
        name: Component name for logging context
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)

    return logger


def log_with_context(
    logger: logging.Logger,
    level: str,
    message: str,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """Log message with additional context

    Args:
        logger: Logger instance
        level: Log level
        message: Log message
        context: Additional context data to include in log
    """
    log_func = getattr(logger, level.lower(), logger.info)
    if context:
        record = logger.makeRecord(
            logger.name,
            getattr(logging, level.upper()),
            "(unknown file)",
            0,
            message,
            (),
            None,
        )
        record.user_data = context
        logger.handle(record)
    else:
        log_func(message)
