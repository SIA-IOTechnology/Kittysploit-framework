#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Correlation context for commands, modules, and sessions (contextvars)."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Dict, Iterator, Optional

_run_id: ContextVar[Optional[str]] = ContextVar("obs_run_id", default=None)
_workspace: ContextVar[Optional[str]] = ContextVar("obs_workspace", default=None)
_command_id: ContextVar[Optional[str]] = ContextVar("obs_command_id", default=None)
_command_name: ContextVar[Optional[str]] = ContextVar("obs_command_name", default=None)
_module_name: ContextVar[Optional[str]] = ContextVar("obs_module_name", default=None)
_session_id: ContextVar[Optional[str]] = ContextVar("obs_session_id", default=None)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def set_run_id(run_id: str) -> None:
    _run_id.set(run_id)


def set_workspace(workspace: Optional[str]) -> None:
    _workspace.set(workspace)


def bind_module(module_name: Optional[str]) -> Token:
    return _module_name.set(module_name)


def bind_session(session_id: Optional[str]) -> Token:
    return _session_id.set(session_id)


def reset_module(token: Token) -> None:
    _module_name.reset(token)


def reset_session(token: Token) -> None:
    _session_id.reset(token)


def get_correlation() -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    run_id = _run_id.get()
    if run_id:
        fields["run_id"] = run_id
    workspace = _workspace.get()
    if workspace:
        fields["workspace"] = workspace
    command_id = _command_id.get()
    if command_id:
        fields["command_id"] = command_id
    command_name = _command_name.get()
    if command_name:
        fields["command"] = command_name
    module_name = _module_name.get()
    if module_name:
        # "module" is reserved on logging.LogRecord (source file name).
        fields["module_name"] = module_name
    session_id = _session_id.get()
    if session_id:
        fields["session_id"] = session_id
    return fields


@contextmanager
def command_span(command_name: str) -> Iterator[str]:
    """Bind command correlation for the duration of a CLI/API command."""
    command_id = _new_id("cmd")
    token_id = _command_id.set(command_id)
    token_name = _command_name.set(command_name)
    try:
        yield command_id
    finally:
        _command_id.reset(token_id)
        _command_name.reset(token_name)


@contextmanager
def module_span(module_name: str, session_id: Optional[str] = None) -> Iterator[None]:
    """Bind module (and optional session) correlation during module execution."""
    tokens = [bind_module(module_name)]
    if session_id:
        tokens.append(bind_session(session_id))
    try:
        yield
    finally:
        for token in reversed(tokens):
            if token.var is _module_name:
                reset_module(token)
            elif token.var is _session_id:
                reset_session(token)
