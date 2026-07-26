#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Save and restore interactive ``current_module`` around multi-step runs."""

from __future__ import annotations

from typing import Any, Optional

from core.output_handler import print_info


def capture_module_context(framework) -> Optional[Any]:
    if framework is None:
        return None
    return getattr(framework, "current_module", None)


def restore_module_context(
    framework,
    previous_module: Optional[Any],
    *,
    announce: bool = True,
) -> None:
    """Restore CLI module context (``back`` when there was no prior module)."""
    if framework is None:
        return
    framework.current_module = previous_module
    if not announce:
        return
    if previous_module is not None:
        name = getattr(previous_module, "name", None) or type(previous_module).__name__
        print_info(f"Restored module context: {name}")
    else:
        print_info("Returned to main command prompt")
