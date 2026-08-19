#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Base class for offline pre-stage modules embedded in generated payloads."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from core.framework.base_module import BaseModule
from core.output_handler import print_error


class Prestage(BaseModule):
    """Offline code embedded in a payload before the first C2 callback."""

    TYPE_MODULE = "prestage"

    # Short identifier used in: set prestage check_vm,daemonize
    PRESTAGE_ID: str = ""

    # Languages this module can emit (python, zig, powershell, ...)
    SUPPORTED_LANGUAGES: List[str] = ["python"]

    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "prestage"

    def prestage_id(self) -> str:
        explicit = str(getattr(self.__class__, "PRESTAGE_ID", "") or "").strip()
        if explicit:
            return explicit
        module_path = str(getattr(self, "module_path", "") or "").strip()
        if module_path:
            return module_path.split("/")[-1]
        return type(self).__name__.lower()

    def supported_languages(self) -> List[str]:
        info = getattr(self.__class__, "__info__", {}) or {}
        langs = info.get("languages") or getattr(self.__class__, "SUPPORTED_LANGUAGES", None) or ["python"]
        return [str(lang).strip().lower() for lang in langs if str(lang).strip()]

    def platform_tokens(self) -> Set[str]:
        info = getattr(self.__class__, "__info__", {}) or {}
        platform = info.get("platform")
        if hasattr(platform, "value"):
            raw = str(platform.value or "all").lower()
        else:
            raw = str(platform or "all").lower()
        if raw in ("multi", "all"):
            return {"all", "multi"}
        return {raw}

    def matches_platform(self, platform: str) -> bool:
        from core.payload_generation.prestage_loader import _platform_compatible

        return _platform_compatible(platform, self.platform_tokens())

    def get_dependencies(self) -> List[str]:
        info = getattr(self.__class__, "__info__", {}) or {}
        deps = info.get("dependencies") or info.get("prestage_dependencies") or []
        return [str(dep).strip() for dep in deps if str(dep).strip()]

    def generate(self, language: str = "python", context: Optional[Dict[str, Any]] = None) -> str:
        lang = str(language or "python").strip().lower()
        supported = self.supported_languages()
        if lang not in supported:
            raise ValueError(
                f"Prestage '{self.prestage_id()}' does not support language '{lang}' "
                f"(supported: {', '.join(supported)})"
            )
        method_name = f"generate_{lang.replace('-', '_')}"
        method = getattr(self, method_name, None)
        if not callable(method):
            raise NotImplementedError(f"{type(self).__name__} must implement {method_name}()")
        return str(method(context or {})).strip()

    def run(self):
        print_error(
            "Prestage modules are embedded at payload generation time. "
            "Use 'set prestage <id>' on a compatible Python or Zig payload, or 'search type:prestage'."
        )
        return False
