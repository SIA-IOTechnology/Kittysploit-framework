#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Framework health diagnostics for the doctor command."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from core.utils.paths import (
    data_dir,
    data_resource,
    data_resource_exists,
    framework_root,
    shared_static_img_dir,
    sound_notify_path,
)
from core.utils.venv_helper import detect_virtualenv

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


class CheckStatus(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class CheckResult:
    category: str
    name: str
    status: CheckStatus
    detail: str = ""
    hint: str = ""


@dataclass
class DoctorReport:
    results: List[CheckResult] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not any(r.status == CheckStatus.FAIL for r in self.results)

    @property
    def counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in CheckStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "healthy": self.healthy,
            "counts": self.counts,
            "checks": [
                {
                    "category": r.category,
                    "name": r.name,
                    "status": r.status.value,
                    "detail": r.detail,
                    "hint": r.hint,
                }
                for r in self.results
            ],
        }


ALL_CATEGORIES = (
    "python",
    "dependencies",
    "zig",
    "docker",
    "tor",
    "db",
    "assets",
    "permissions",
    "wordlists",
    "marketplace",
)

_REQUIRED_ASSETS: Sequence[tuple[tuple[str, ...], bool]] = (
    (("syscall", "syscalls.json"), True),
    (("syscall", "x86_64.json"), True),
    (("vendors", "oui.json"), True),
    (("default_password.json",), True),
    (("metasploit", "rpc_config.json"), False),
    (("sound", "notify.wav"), False),
)

_KNOWN_WORDLISTS: Sequence[tuple[str, ...]] = (
    ("wordlists", "dns.txt"),
    ("wordlists", "lfi", "linux.txt"),
    ("wordlists", "lfi", "win.txt"),
    ("wordlists", "lfi", "win_base.txt"),
)


def _data_asset_label(parts: tuple[str, ...]) -> str:
    return "data/" + "/".join(parts)


def _add(report: DoctorReport, result: CheckResult) -> None:
    report.results.append(result)


def _parse_dep_name(spec: str) -> Optional[str]:
    spec = spec.strip()
    if not spec:
        return None
    if ";" in spec:
        spec, marker = spec.split(";", 1)
        marker = marker.strip().lower()
        if "python_version" in marker:
            py = sys.version_info
            if "< '3.11'" in marker and py >= (3, 11):
                return None
            if ">= '3.11'" in marker and py < (3, 11):
                return None
    return spec.split(">=")[0].split("==")[0].split("[")[0].strip()


def _load_pyproject_deps(root: Path) -> List[str]:
    pyproject = root / "pyproject.toml"
    if tomllib is None or not pyproject.is_file():
        return []
    with open(pyproject, "rb") as handle:
        data = tomllib.load(handle)
    project = data.get("project") or {}
    deps = list(project.get("dependencies") or [])
    optional = project.get("optional-dependencies") or {}
    if platform.system() == "Windows":
        deps.extend(optional.get("windows") or [])
    return deps


def _find_zig() -> Optional[str]:
    from core.lib.compiler.zig_paths import find_zig_executable

    return find_zig_executable()


def _zig_version(zig_path: str) -> str:
    result = subprocess.run(
        [zig_path, "version"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        return ""
    return (result.stdout or result.stderr or "").strip()


def _registry_url() -> str:
    try:
        from core.config import Config

        url = Config.get_instance().get_config_value_by_path("registry.url")
        if url:
            return str(url).rstrip("/")
    except Exception:
        pass

    config_path = Path("config") / "kittysploit.toml"
    if config_path.is_file() and tomllib is not None:
        try:
            with open(config_path, "rb") as handle:
                data = tomllib.load(handle)
            url = (data.get("registry") or {}).get("url")
            if url:
                return str(url).rstrip("/")
        except Exception:
            pass

    user_cfg = Path.home() / ".kittysploit" / "registry_config.json"
    if user_cfg.is_file():
        try:
            import json

            with open(user_cfg, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            url = data.get("base_url")
            if url:
                return str(url).rstrip("/")
        except Exception:
            pass

    return "https://app.kittysploit.com"


def _extensions_dir(root: Path) -> Path:
    try:
        from core.config import Config

        rel = Config.get_instance().get_config_value_by_path("registry.extensions_dir")
        if rel:
            path = Path(rel)
            return path if path.is_absolute() else root / path
    except Exception:
        pass
    return root / "extensions"


class Doctor:
    """Run environment and framework health checks."""

    def __init__(self, framework: Any = None):
        self.framework = framework
        self.root = framework_root()

    def run(self, categories: Optional[Sequence[str]] = None) -> DoctorReport:
        selected = set(categories or ALL_CATEGORIES)
        report = DoctorReport()

        runners = {
            "python": self._check_python,
            "dependencies": self._check_dependencies,
            "zig": self._check_zig,
            "docker": self._check_docker,
            "tor": self._check_tor,
            "db": self._check_db,
            "assets": self._check_assets,
            "permissions": self._check_permissions,
            "wordlists": self._check_wordlists,
            "marketplace": self._check_marketplace,
        }
        for name in ALL_CATEGORIES:
            if name in selected:
                runners[name](report)
        return report

    def _check_python(self, report: DoctorReport) -> None:
        version = sys.version_info
        detail = f"{sys.version.split()[0]} ({sys.executable})"
        if version < (3, 9):
            _add(
                report,
                CheckResult(
                    "python",
                    "version",
                    CheckStatus.FAIL,
                    detail,
                    "KittySploit requires Python 3.9 or newer.",
                ),
            )
            return
        _add(report, CheckResult("python", "version", CheckStatus.OK, detail))

        venv = detect_virtualenv()
        if venv:
            detail = venv
            if not os.environ.get("VIRTUAL_ENV"):
                detail = f"{venv} (interpreter, not shell-activated)"
            _add(report, CheckResult("python", "virtualenv", CheckStatus.OK, detail))
        else:
            _add(
                report,
                CheckResult(
                    "python",
                    "virtualenv",
                    CheckStatus.WARN,
                    "No active virtual environment detected",
                    "Use a venv to isolate framework dependencies.",
                ),
            )

    def _check_dependencies(self, report: DoctorReport) -> None:
        if self.root is None:
            _add(
                report,
                CheckResult(
                    "dependencies",
                    "framework_root",
                    CheckStatus.FAIL,
                    "Framework root not found",
                ),
            )
            return

        specs = _load_pyproject_deps(self.root)
        if not specs:
            _add(
                report,
                CheckResult(
                    "dependencies",
                    "pyproject",
                    CheckStatus.WARN,
                    "Could not load dependency list from pyproject.toml",
                ),
            )
            return

        from core.framework.utils.dependencies import DependencyManager

        dep_manager = DependencyManager()
        missing: List[str] = []
        for spec in specs:
            package = _parse_dep_name(spec)
            if not package:
                continue
            try:
                results = dep_manager.check_dependencies([package], optional=True)
                if not results.get(package, False):
                    missing.append(package)
            except Exception:
                missing.append(package)

        if missing:
            _add(
                report,
                CheckResult(
                    "dependencies",
                    "python_packages",
                    CheckStatus.FAIL,
                    f"{len(missing)} missing: {', '.join(missing)}",
                    "pip install -e .  (or install missing packages individually)",
                ),
            )
            return

        _add(
            report,
            CheckResult(
                "dependencies",
                "python_packages",
                CheckStatus.OK,
                f"{len(specs)} declared dependencies importable",
            ),
        )

    def _check_zig(self, report: DoctorReport) -> None:
        zig_path = _find_zig()
        if not zig_path:
            _add(
                report,
                CheckResult(
                    "zig",
                    "compiler",
                    CheckStatus.WARN,
                    "Zig not found in PATH or bundled location",
                    "Required for Zig payloads and py2exe compilation. Install from https://ziglang.org/download/",
                ),
            )
            return
        version = _zig_version(zig_path)
        _add(
            report,
            CheckResult(
                "zig",
                "compiler",
                CheckStatus.OK,
                f"{version or 'available'} ({zig_path})",
            ),
        )

    def _check_docker(self, report: DoctorReport) -> None:
        if shutil.which("docker") is None:
            _add(
                report,
                CheckResult(
                    "docker",
                    "cli",
                    CheckStatus.WARN,
                    "docker CLI not found in PATH",
                    "Install Docker to use docker_environment modules and environments command.",
                ),
            )
            return

        try:
            import docker

            client = docker.from_env()
            client.ping()
            info = client.version()
            detail = info.get("Version") or info.get("ApiVersion") or "daemon reachable"
            _add(report, CheckResult("docker", "daemon", CheckStatus.OK, str(detail)))
        except Exception as exc:
            _add(
                report,
                CheckResult(
                    "docker",
                    "daemon",
                    CheckStatus.WARN,
                    f"CLI present but daemon unreachable: {exc}",
                    "Start Docker Desktop or the docker service.",
                ),
            )

    def _check_tor(self, report: DoctorReport) -> None:
        host = "127.0.0.1"
        ports = (9050, 9150)
        available_ports: List[int] = []

        if self.framework and hasattr(self.framework, "tor_manager"):
            manager = self.framework.tor_manager
            for port in ports:
                if manager.check_tor_available(host, port):
                    available_ports.append(port)
        else:
            import socket

            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    if sock.connect_ex((host, port)) == 0:
                        available_ports.append(port)
                finally:
                    sock.close()

        if available_ports:
            enabled = (
                getattr(getattr(self.framework, "tor_manager", None), "enabled", False)
                if self.framework
                else False
            )
            detail = f"SOCKS proxy on port(s) {', '.join(map(str, available_ports))}"
            if enabled:
                detail += " (enabled in framework)"
            _add(report, CheckResult("tor", "socks_proxy", CheckStatus.OK, detail))
            return

        _add(
            report,
            CheckResult(
                "tor",
                "socks_proxy",
                CheckStatus.WARN,
                "No Tor SOCKS proxy on 127.0.0.1:9050 or :9150",
                "Start tor service or Tor Browser, then use: tor enable",
            ),
        )

    def _check_db(self, report: DoctorReport) -> None:
        if not self.framework or not hasattr(self.framework, "db_manager"):
            _add(
                report,
                CheckResult(
                    "db",
                    "manager",
                    CheckStatus.FAIL,
                    "Database manager not initialized",
                ),
            )
            return

        db_manager = self.framework.db_manager
        db_path = Path(db_manager._resolve_db_path())
        workspace = getattr(self.framework, "current_workspace", "default") or "default"

        if db_path.is_file():
            size = db_path.stat().st_size
            _add(
                report,
                CheckResult(
                    "db",
                    "database_file",
                    CheckStatus.OK,
                    f"{db_path} ({size} bytes)",
                ),
            )
        else:
            _add(
                report,
                CheckResult(
                    "db",
                    "database_file",
                    CheckStatus.WARN,
                    f"Database file not found yet: {db_path}",
                    "It will be created on first workspace use.",
                ),
            )

        session = db_manager.get_session(workspace)
        if session is None:
            _add(
                report,
                CheckResult(
                    "db",
                    "workspace_session",
                    CheckStatus.FAIL,
                    f"Cannot open session for workspace '{workspace}'",
                ),
            )
            return

        try:
            from sqlalchemy import text

            session.execute(text("SELECT 1"))
            _add(
                report,
                CheckResult(
                    "db",
                    "workspace_session",
                    CheckStatus.OK,
                    f"Workspace '{workspace}' session OK",
                ),
            )
        except Exception as exc:
            _add(
                report,
                CheckResult(
                    "db",
                    "workspace_session",
                    CheckStatus.FAIL,
                    str(exc),
                ),
            )

        if hasattr(self.framework, "encryption_manager"):
            from core.encryption_manager import EncryptionManager

            if EncryptionManager.is_available():
                _add(report, CheckResult("db", "encryption", CheckStatus.OK, "cryptography library available"))
            else:
                _add(
                    report,
                    CheckResult(
                        "db",
                        "encryption",
                        CheckStatus.WARN,
                        "cryptography library not installed",
                        "pip install cryptography",
                    ),
                )

    def _check_assets(self, report: DoctorReport) -> None:
        if self.root is None:
            _add(
                report,
                CheckResult("assets", "framework_root", CheckStatus.FAIL, "Framework root not found"),
            )
            return

        missing_required: List[str] = []
        missing_optional: List[str] = []
        for parts, required in _REQUIRED_ASSETS:
            label = _data_asset_label(parts)
            if data_resource_exists(*parts):
                continue
            if required:
                missing_required.append(label)
            else:
                missing_optional.append(label)

        static_img = shared_static_img_dir()
        if not static_img.is_dir():
            try:
                rel = str(static_img.relative_to(self.root))
            except ValueError:
                rel = str(static_img)
            missing_optional.append(rel)

        if missing_required:
            _add(
                report,
                CheckResult(
                    "assets",
                    "bundled_files",
                    CheckStatus.FAIL,
                    f"Missing: {', '.join(missing_required)}",
                ),
            )
        else:
            _add(
                report,
                CheckResult(
                    "assets",
                    "bundled_files",
                    CheckStatus.OK,
                    f"{len(_REQUIRED_ASSETS) - len(missing_optional)} core assets present",
                ),
            )

        if missing_optional:
            _add(
                report,
                CheckResult(
                    "assets",
                    "optional_files",
                    CheckStatus.WARN,
                    f"Missing optional: {', '.join(missing_optional)}",
                ),
            )

        notify = sound_notify_path()
        if notify:
            _add(report, CheckResult("assets", "notify_sound", CheckStatus.OK, str(notify)))
        else:
            _add(
                report,
                CheckResult(
                    "assets",
                    "notify_sound",
                    CheckStatus.WARN,
                    "data/sound/notify.wav not found (sound test will fail)",
                ),
            )

    def _check_permissions(self, report: DoctorReport) -> None:
        paths: Set[Path] = set()
        if self.root is not None:
            paths.add(self.root / "database")
            paths.add(self.root / "modules")
            paths.add(data_dir())

        paths.add(Path.home() / ".kittysploit")

        if self.framework:
            workspaces_dir = getattr(self.framework, "workspaces_dir", None)
            if workspaces_dir:
                ws = Path(workspaces_dir)
                paths.add(ws if ws.is_absolute() else (self.root or Path.cwd()) / ws)

            if hasattr(self.framework, "db_manager"):
                db_parent = Path(self.framework.db_manager._resolve_db_path()).parent
                paths.add(db_parent)

        failures: List[str] = []
        warnings: List[str] = []
        for path in sorted(paths, key=str):
            if path.is_file():
                target = path.parent
            else:
                target = path
            if target.exists():
                if not os.access(target, os.W_OK):
                    failures.append(f"{target} (not writable)")
                elif not os.access(target, os.R_OK):
                    failures.append(f"{target} (not readable)")
            else:
                parent = target.parent
                if parent.exists() and os.access(parent, os.W_OK):
                    warnings.append(f"{target} (will be created)")
                else:
                    failures.append(f"{target} (parent not writable)")

        if failures:
            _add(
                report,
                CheckResult(
                    "permissions",
                    "filesystem",
                    CheckStatus.FAIL,
                    "; ".join(failures),
                ),
            )
        elif warnings:
            _add(
                report,
                CheckResult(
                    "permissions",
                    "filesystem",
                    CheckStatus.OK,
                    f"Writable; pending: {', '.join(warnings)}",
                ),
            )
        else:
            _add(report, CheckResult("permissions", "filesystem", CheckStatus.OK, f"{len(paths)} paths checked"))

    def _check_wordlists(self, report: DoctorReport) -> None:
        if self.root is None:
            _add(
                report,
                CheckResult("wordlists", "framework_root", CheckStatus.FAIL, "Framework root not found"),
            )
            return

        present = 0
        missing: List[str] = []
        empty: List[str] = []
        for parts in _KNOWN_WORDLISTS:
            label = _data_asset_label(parts)
            if not data_resource_exists(*parts):
                missing.append(label)
                continue
            present += 1
            try:
                size = data_resource(*parts).stat().st_size
            except (OSError, AttributeError, TypeError):
                size = 1
            if size == 0:
                empty.append(label)

        if missing:
            _add(
                report,
                CheckResult(
                    "wordlists",
                    "bundled_wordlists",
                    CheckStatus.FAIL,
                    f"Missing {len(missing)}: {', '.join(missing)}",
                ),
            )
        else:
            _add(
                report,
                CheckResult(
                    "wordlists",
                    "bundled_wordlists",
                    CheckStatus.OK,
                    f"{present} wordlists present",
                ),
            )

        if empty:
            _add(
                report,
                CheckResult(
                    "wordlists",
                    "non_empty",
                    CheckStatus.WARN,
                    f"Empty files: {', '.join(empty)}",
                ),
            )

    def _check_marketplace(self, report: DoctorReport) -> None:
        url = _registry_url()
        catalog_endpoints = (
            ("new", f"{url}/api/cli/market/modules"),
            ("legacy", f"{url}/api/registry/extensions"),
        )
        try:
            import requests

            last_status: Optional[int] = None
            last_error = ""
            for label, endpoint in catalog_endpoints:
                try:
                    response = requests.get(
                        endpoint,
                        params={"page": 1, "per_page": 1},
                        timeout=8,
                    )
                    if response.ok:
                        detail = url
                        if label == "legacy":
                            detail = f"{url} (legacy registry API)"
                        _add(
                            report,
                            CheckResult("marketplace", "registry_api", CheckStatus.OK, detail),
                        )
                        break
                    last_status = response.status_code
                    last_error = f"{endpoint} returned HTTP {response.status_code}"
                except Exception as exc:
                    last_error = f"{endpoint}: {exc}"
            else:
                if last_status is not None:
                    _add(
                        report,
                        CheckResult(
                            "marketplace",
                            "registry_api",
                            CheckStatus.WARN,
                            f"{url} returned HTTP {last_status}",
                        ),
                    )
                else:
                    _add(
                        report,
                        CheckResult(
                            "marketplace",
                            "registry_api",
                            CheckStatus.WARN,
                            f"Cannot reach {url}: {last_error}",
                            "Offline installs still work from local paths (market install ./apps/...).",
                        ),
                    )
        except Exception as exc:
            _add(
                report,
                CheckResult(
                    "marketplace",
                    "registry_api",
                    CheckStatus.WARN,
                    f"Cannot reach {url}: {exc}",
                    "Offline installs still work from local paths (market install ./apps/...).",
                ),
            )

        if self.root is None:
            return

        apps_root = self.root / "apps"
        local_apps: List[str] = []
        if apps_root.is_dir():
            for app_dir in sorted(apps_root.iterdir()):
                manifest = app_dir / "extension.toml"
                if manifest.is_file():
                    local_apps.append(app_dir.name)

        ext_dir = _extensions_dir(self.root)
        installed = 0
        if ext_dir.is_dir():
            for entry in ext_dir.iterdir():
                if entry.is_dir() and any(entry.rglob("extension.toml")):
                    installed += 1

        from core.utils.marketplace_apps import OFFICIAL_APP_PACKAGES, discover_app_src

        discoverable = 0
        if self.root is not None:
            for _app_id, package_name in OFFICIAL_APP_PACKAGES.items():
                if discover_app_src(self.root, package_name) is not None:
                    discoverable += 1

        detail_parts = [
            f"{len(local_apps)} app sources under apps/",
            f"{installed} installed under {ext_dir.name}/",
            f"{discoverable}/{len(OFFICIAL_APP_PACKAGES)} official apps on disk",
        ]
        if local_apps:
            detail_parts.append("sources: " + ", ".join(local_apps))

        status = CheckStatus.OK if discoverable or installed or local_apps else CheckStatus.WARN
        _add(
            report,
            CheckResult(
                "marketplace",
                "local_extensions",
                status,
                "; ".join(detail_parts),
                "Use: market list | market install <id>",
            ),
        )
