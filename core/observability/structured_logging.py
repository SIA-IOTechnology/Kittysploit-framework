#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""JSON structured logging with correlation fields."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from core.observability.context import get_correlation


# Keys reserved by logging.LogRecord — cannot be passed via logger.*(..., extra=...).
_LOG_RECORD_RESERVED = frozenset({
    "name",
    "msg",
    "args",
    "created",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "exc_info",
    "exc_text",
    "thread",
    "threadName",
    "message",
    "asctime",
})

# Semantic renames when a reserved key must be preserved in structured output.
_LOG_EXTRA_RENAMES = {
    "module": "module_name",
    "name": "logger_name",
    "message": "detail_message",
}


def sanitize_log_extra(extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not extra:
        return {}
    safe: Dict[str, Any] = {}
    for key, value in extra.items():
        if key in _LOG_RECORD_RESERVED:
            safe[_LOG_EXTRA_RENAMES.get(key, f"{key}_field")] = value
        else:
            safe[key] = value
    return safe


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class CorrelationFilter(logging.Filter):
    """Inject correlation fields into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in get_correlation().items():
            if key in _LOG_RECORD_RESERVED:
                key = _LOG_EXTRA_RENAMES.get(key, f"{key}_field")
            setattr(record, key, value)
        return True


class StructuredJSONFormatter(logging.Formatter):
    """Format log records as a single JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": _utc_timestamp(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(get_correlation())
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in payload:
                continue
            if key in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
            }:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False)


class JSONLLogHandler(logging.Handler):
    """Append structured JSON log lines to a file."""

    def __init__(self, file_path: Path):
        super().__init__()
        self.file_path = file_path
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = open(self.file_path, "a", encoding="utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        if self._closed:
            return
        try:
            self.acquire()
            try:
                if self._closed or self._stream is None or self._stream.closed:
                    return
                line = self.format(record)
                self._stream.write(line + "\n")
                self._stream.flush()
            finally:
                self.release()
        except (ValueError, OSError):
            # Stream closed while background threads are still logging.
            return
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        self.acquire()
        try:
            if self._stream is not None and not self._stream.closed:
                self._stream.close()
            self._stream = None
        finally:
            self.release()
        super().close()


def _detach_jsonl_handlers(root: logging.Logger, log_path: Optional[Path] = None) -> None:
    for handler in list(root.handlers):
        if not isinstance(handler, JSONLLogHandler):
            continue
        if log_path is not None and handler.file_path != log_path:
            continue
        root.removeHandler(handler)
        handler.close()


def configure_structured_logging(
    *,
    log_path: Path,
    level: int = logging.INFO,
    include_console: bool = False,
) -> JSONLLogHandler:
    """
    Attach JSONL structured logging to the root logger.

    Returns the file handler so the caller can close it on shutdown.
    """
    root = logging.getLogger()
    root.setLevel(min(root.level, level))

    correlation_filter = CorrelationFilter()
    json_formatter = StructuredJSONFormatter()

    _detach_jsonl_handlers(root, log_path)

    file_handler = JSONLLogHandler(log_path)
    file_handler.setLevel(level)
    file_handler.addFilter(correlation_filter)
    file_handler.setFormatter(json_formatter)
    root.addHandler(file_handler)

    if include_console:
        console = logging.StreamHandler()
        console.setLevel(level)
        console.addFilter(correlation_filter)
        console.setFormatter(json_formatter)
        root.addHandler(console)

    return file_handler


def env_flag(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}
