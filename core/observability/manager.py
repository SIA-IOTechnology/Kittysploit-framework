#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Central observability setup: JSONL metrics, structured logs, correlation."""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from core.config import Config
from core.observability.context import (
    command_span,
    get_correlation,
    module_span,
    set_run_id,
    set_workspace,
)
from core.observability.structured_logging import (
    configure_structured_logging,
    env_flag,
    sanitize_log_extra,
)

logger = logging.getLogger(__name__)


class ObservabilityManager:
    """Wire metrics exporters and structured logging with shared correlation."""

    DEFAULT_DIR = "~/.kittysploit/observability"

    def __init__(self, metrics_collector: Any) -> None:
        self.metrics_collector = metrics_collector
        self.enabled = False
        self.run_id = f"run_{uuid.uuid4().hex[:12]}"
        self.base_dir: Optional[Path] = None
        self._log_handler = None
        self._metric_exporters: List[Any] = []

    def configure(self, workspace: Optional[str] = None) -> None:
        """Read config / env and enable exporters when observability is on."""
        cfg = self._resolve_config()
        self.enabled = bool(cfg.get("enabled", True))
        if not self.enabled:
            return

        self.run_id = f"run_{uuid.uuid4().hex[:12]}"
        set_run_id(self.run_id)
        if workspace:
            set_workspace(workspace)

        self.base_dir = Path(os.path.expanduser(str(cfg.get("dir", self.DEFAULT_DIR))))
        self.base_dir.mkdir(parents=True, exist_ok=True)

        if cfg.get("metrics_jsonl", True):
            self._setup_metrics_jsonl(self.base_dir / "metrics.jsonl")

        if cfg.get("structured_logs", True) and cfg.get("logs_jsonl", True):
            level_name = str(cfg.get("log_level", "INFO")).upper()
            level = getattr(logging, level_name, logging.INFO)
            if self._log_handler is not None:
                root = logging.getLogger()
                root.removeHandler(self._log_handler)
                self._log_handler.close()
                self._log_handler = None
            self._log_handler = configure_structured_logging(
                log_path=self.base_dir / "logs.jsonl",
                level=level,
                include_console=bool(cfg.get("include_console", False)),
            )

        logger.info(
            "Observability enabled",
            extra={
                "event": "observability.start",
                "observability_dir": str(self.base_dir),
            },
        )

    def update_workspace(self, workspace: str) -> None:
        set_workspace(workspace)

    def _resolve_config(self) -> Dict[str, Any]:
        config = Config.get_instance().get_config_value("observability") or {}
        defaults = {
            "enabled": True,
            "structured_logs": True,
            "metrics_jsonl": True,
            "logs_jsonl": True,
            "dir": self.DEFAULT_DIR,
            "log_level": "INFO",
            "include_console": False,
        }
        merged = {**defaults, **config}
        if not env_flag("KITTYSPLOIT_OBSERVABILITY", merged["enabled"]):
            merged["enabled"] = False
        env_dir = os.environ.get("KITTYSPLOIT_OBSERVABILITY_DIR")
        if env_dir:
            merged["dir"] = env_dir
        return merged

    def _setup_metrics_jsonl(self, path: Path) -> None:
        from core.framework.utils.metrics_exporters import JSONLFileExporter

        exporter = JSONLFileExporter(str(path))
        if self.metrics_collector.add_exporter(exporter):
            self._metric_exporters.append(exporter)

    def correlation_metadata(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        meta = get_correlation()
        if extra:
            meta.update(extra)
        return meta

    def log_event(
        self,
        event: str,
        message: str,
        *,
        level: int = logging.INFO,
        **fields: Any,
    ) -> None:
        if not self.enabled:
            return
        payload = sanitize_log_extra({"event": event, **fields})
        logger.log(level, message, extra=payload)

    @contextmanager
    def track_command(self, command_name: str, args: Optional[List[str]] = None) -> Iterator[str]:
        with command_span(command_name) as command_id:
            self.log_event(
                "command.start",
                f"Command started: {command_name}",
                command_args=list(args or []),
            )
            try:
                yield command_id
                self.log_event("command.finish", f"Command finished: {command_name}")
            except Exception as exc:
                self.log_event(
                    "command.error",
                    f"Command failed: {command_name}",
                    level=logging.ERROR,
                    error=str(exc),
                )
                raise

    @contextmanager
    def track_module(
        self,
        module_name: str,
        *,
        session_id: Optional[str] = None,
        framework: Any = None,
    ) -> Iterator[None]:
        resolved_session = session_id or self.resolve_session_id(framework)
        with module_span(module_name, resolved_session):
            self.log_event(
                "module.start",
                f"Module execution started: {module_name}",
                module_name=module_name,
                session_id=resolved_session,
            )
            try:
                yield
                self.log_event(
                    "module.finish",
                    f"Module execution finished: {module_name}",
                    module_name=module_name,
                    session_id=resolved_session,
                )
            except Exception as exc:
                self.log_event(
                    "module.error",
                    f"Module execution failed: {module_name}",
                    level=logging.ERROR,
                    module_name=module_name,
                    session_id=resolved_session,
                    error=str(exc),
                )
                raise

    def resolve_session_id(self, framework: Any = None) -> Optional[str]:
        correlation = get_correlation()
        if correlation.get("session_id"):
            return correlation["session_id"]
        if framework is None:
            return None
        output_handler = getattr(framework, "output_handler", None)
        if output_handler and hasattr(output_handler, "get_current_session_id"):
            session_id = output_handler.get_current_session_id()
            if session_id:
                return str(session_id)
        return None

    def read_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._read_jsonl(self.base_dir / "logs.jsonl" if self.base_dir else None, limit)

    def read_metrics(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._read_jsonl(self.base_dir / "metrics.jsonl" if self.base_dir else None, limit)

    @staticmethod
    def _read_jsonl(path: Optional[Path], limit: int) -> List[Dict[str, Any]]:
        if path is None or not path.is_file():
            return []
        import json

        lines = path.read_text(encoding="utf-8").splitlines()
        records: List[Dict[str, Any]] = []
        for line in lines[-max(1, limit) :]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def shutdown(self) -> None:
        if self._log_handler is not None:
            root = logging.getLogger()
            root.removeHandler(self._log_handler)
            self._log_handler.close()
            self._log_handler = None
        if self.metrics_collector is not None:
            self.metrics_collector.close_exporters()
        self._metric_exporters.clear()
        self.enabled = False
