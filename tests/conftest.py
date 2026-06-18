"""Shared pytest fixtures for KittySploit smoke tests."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Stable module used across command smoke tests.
SAMPLE_PAYLOAD = "payloads/singles/cmd/unix/bash_reverse_tcp"
SAMPLE_SEARCH_TERM = "bash"


def _deps_available() -> bool:
    """Return True when core runtime dependencies are importable."""
    return importlib.util.find_spec("sqlalchemy") is not None


requires_runtime_deps = pytest.mark.skipif(
    not _deps_available(),
    reason="Install project dependencies first (pip install -e .)",
)


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture
def framework(project_root, monkeypatch, tmp_path):
    """Framework instance with an isolated SQLite database."""
    monkeypatch.chdir(project_root)
    db_path = tmp_path / "smoke.db"
    monkeypatch.setenv("KITTYSPLOIT_DB_PATH", str(db_path))

    from core.framework.framework import Framework

    fw = Framework(clean_sessions=True)
    try:
        fw.sync_modules_now()
        yield fw
    finally:
        fw.db_manager.close_all()


@pytest.fixture
def command_registry(framework):
    from core.output_handler import OutputHandler
    from core.session import Session
    from interfaces.command_system.command_registry import CommandRegistry

    return CommandRegistry(framework, Session(), OutputHandler())


@pytest.fixture
def load_sample_payload(framework, command_registry):
    """Select the bash reverse TCP payload for generate/show tests."""
    ok = command_registry.execute_command("use", [SAMPLE_PAYLOAD])
    assert ok, f"failed to load {SAMPLE_PAYLOAD}"
    assert framework.current_module is not None
    return framework.current_module
