#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Vagrant-based lab environments (Metasploitable3 Windows, etc.)."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.framework.base_module import BaseModule
from core.framework.option import OptBool, OptInteger, OptPort, OptString
from core.output_handler import print_error, print_info, print_status, print_success, print_warning
from core.utils.paths import framework_root


class VagrantEnvironment(BaseModule):
    """Provision isolated lab VMs through Vagrant with host-only port forwards."""

    TYPE_MODULE = "vagrant_environment"

    vagrant_target = OptString("win2k8", "Vagrant machine name inside the Vagrantfile", True)
    vagrant_box = OptString(
        "rapid7/metasploitable3-win2k8",
        "Vagrant box name (must be built/added locally)",
        True,
    )
    workspace_dir = OptString("", "Workspace directory containing the Vagrantfile", False)
    vagrantfile_template = OptString(
        "",
        "Bundled Vagrantfile template path relative to repo root",
        False,
    )
    host_bind = OptString("127.0.0.1", "Host bind address for forwarded ports", True)
    ready_timeout = OptInteger(600, "Timeout in seconds for VM readiness checks", True)
    provider = OptString("virtualbox", "Preferred Vagrant provider", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._type = "vagrant_environment"
        self._last_status: Dict[str, Any] = {}

    def _repo_root(self) -> Path:
        root = framework_root()
        return root if root is not None else Path.cwd()

    def resolve_workspace(self) -> Path:
        custom = str(getattr(self, "workspace_dir", "") or "").strip()
        if custom:
            return Path(custom).expanduser().resolve()
        return (self._repo_root() / "artifacts" / "labs" / "ms3-windows" / "workspace").resolve()

    def _ensure_workspace(self) -> Path:
        workspace = self.resolve_workspace()
        workspace.mkdir(parents=True, exist_ok=True)
        vagrantfile = workspace / "Vagrantfile"
        if vagrantfile.is_file():
            return workspace

        template = str(getattr(self, "vagrantfile_template", "") or "").strip()
        if not template:
            raise FileNotFoundError(
                f"No Vagrantfile in {workspace} and no vagrantfile_template configured"
            )
        source = (self._repo_root() / template).resolve()
        if not source.is_file():
            raise FileNotFoundError(f"Vagrantfile template not found: {source}")
        shutil.copy2(source, vagrantfile)
        print_success(f"Installed Vagrantfile template at {vagrantfile}")
        return workspace

    def _vagrant_env(self, workspace: Path) -> Dict[str, str]:
        env = os.environ.copy()
        env.setdefault("MS3_WIN_BOX", str(getattr(self, "vagrant_box", "") or ""))
        env.setdefault("MS3_HOST_BIND", str(getattr(self, "host_bind", "127.0.0.1") or "127.0.0.1"))
        env.setdefault("VAGRANT_DISABLE_VBOXSYMLINKCREATE", "1")
        env["VAGRANT_CWD"] = str(workspace)
        return env

    def _run_vagrant(
        self,
        workspace: Path,
        args: Sequence[str],
        *,
        timeout: Optional[int] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        command = ["vagrant", *args]
        print_status(f"Running: {' '.join(command)} (cwd={workspace})")
        return subprocess.run(
            command,
            cwd=str(workspace),
            env=self._vagrant_env(workspace),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )

    def check_vagrant(self) -> bool:
        try:
            result = subprocess.run(
                ["vagrant", "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except FileNotFoundError:
            print_error("Vagrant is not installed or not on PATH.")
            print_info("Install Vagrant and a provider (VirtualBox/QEMU) before starting this lab.")
            return False
        if result.returncode != 0:
            print_error(result.stderr.strip() or "Vagrant check failed")
            return False
        print_success(result.stdout.strip() or "Vagrant available")
        return True

    def wait_for_service(self, host: str, port: int, timeout: int = 60) -> bool:
        print_status(f"Waiting for service on {host}:{port}...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    print_success(f"Service available on {host}:{port}")
                    return True
            except OSError:
                time.sleep(1)
        print_error(f"Timeout waiting for {host}:{port}")
        return False

    def readiness_checks(self) -> List[Tuple[str, str, int]]:
        """Return (label, host, port) tuples — override in subclasses."""
        host = str(getattr(self, "host_bind", "127.0.0.1") or "127.0.0.1")
        return []

    def wait_for_readiness(self) -> bool:
        checks = self.readiness_checks()
        if not checks:
            return True
        timeout = int(getattr(self, "ready_timeout", 600) or 600)
        per_check = max(45, timeout // max(1, len(checks)))
        print_status(f"Running {len(checks)} readiness checks (budget={timeout}s)...")
        for label, host, port in checks:
            if not self.wait_for_service(host, port, timeout=per_check):
                print_error(f"Readiness check failed: {label} on {host}:{port}")
                return False
        print_success("All readiness checks passed")
        return True

    def vm_status(self, workspace: Path) -> str:
        try:
            result = self._run_vagrant(
                workspace,
                ["status", str(getattr(self, "vagrant_target", "win2k8"))],
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return "unknown"
        output = (result.stdout or "") + (result.stderr or "")
        lowered = output.lower()
        if "running" in lowered:
            return "running"
        if "poweroff" in lowered or "saved" in lowered:
            return "stopped"
        if "not created" in lowered:
            return "not_created"
        return "unknown"

    def start_vm(self) -> bool:
        if not self.check_vagrant():
            return False
        try:
            workspace = self._ensure_workspace()
        except FileNotFoundError as exc:
            print_error(str(exc))
            return False

        target = str(getattr(self, "vagrant_target", "win2k8") or "win2k8")
        status = self.vm_status(workspace)
        if status == "running":
            print_success(f"Vagrant VM '{target}' is already running")
            self._last_status = {"workspace": str(workspace), "status": status}
            return True

        timeout = int(getattr(self, "ready_timeout", 600) or 600)
        try:
            result = self._run_vagrant(
                workspace,
                ["up", target, "--provider", str(getattr(self, "provider", "virtualbox") or "virtualbox")],
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            print_error(f"Vagrant up timed out after {timeout}s")
            return False

        if result.returncode != 0:
            print_error(result.stderr.strip() or result.stdout.strip() or "vagrant up failed")
            if "box" in (result.stderr or "").lower() and "not found" in (result.stderr or "").lower():
                print_info(
                    "Build or add the box first, e.g. "
                    "`vagrant box add rapid7/metasploitable3-win2k8 <path-to.box>`"
                )
            return False

        self._last_status = {"workspace": str(workspace), "status": "running"}
        print_success(f"Vagrant VM '{target}' started")
        return True

    def destroy_vm(self) -> bool:
        if not self.check_vagrant():
            return False
        workspace = self.resolve_workspace()
        if not (workspace / "Vagrantfile").is_file():
            return True
        target = str(getattr(self, "vagrant_target", "win2k8") or "win2k8")
        try:
            result = self._run_vagrant(
                workspace,
                ["destroy", target, "-f"],
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired:
            print_error("vagrant destroy timed out")
            return False
        if result.returncode != 0:
            print_warning(result.stderr.strip() or "vagrant destroy returned non-zero")
        return True

    def reset_lab(self) -> bool:
        print_status("Resetting Vagrant lab VM...")
        if not self.destroy_vm():
            return False
        return self.start_vm() and self.wait_for_readiness()

    def on_environment_ready(self) -> bool:
        target = str(getattr(self, "vagrant_target", "win2k8") or "win2k8")
        print_success(f"Vagrant lab VM '{target}' is ready")
        print_info(f"Workspace: {self.resolve_workspace()}")
        return True

    def run(self, *args, **kwargs):
        if not self.start_vm():
            return False
        if not self.wait_for_readiness():
            print_warning("VM started but readiness checks did not all pass.")
            return False
        return self.on_environment_ready()
