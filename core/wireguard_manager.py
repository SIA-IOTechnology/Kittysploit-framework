#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Multi-platform WireGuard tunnel bring-up for Academy Rooms (split-tunnel only)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

from core.output_handler import print_error, print_info, print_success, print_warning
from core.room_client import WireGuardPeerConfig

INTERFACE_NAME = "ksroom0"
WINDOWS_TUNNEL_NAME = "KittySploitRoom"
WG_INSTALL_HINT = (
    "Install WireGuard once, then re-run: https://www.wireguard.com/install/"
)
WG_INSTALL_TIMEOUT = 600  # package installs can take several minutes


class WireGuardManager:
    """Activate / deactivate a system WireGuard tunnel from a peer config."""

    def __init__(self, conf_dir: Optional[Path] = None):
        self.conf_dir = conf_dir or (Path.home() / ".kittysploit" / "rooms")
        self.conf_dir.mkdir(parents=True, exist_ok=True)
        self.interface_name = INTERFACE_NAME
        self._active_conf: Optional[Path] = None
        self._platform = platform.system().lower()

    def detect(self) -> Dict[str, Any]:
        """Return availability of WireGuard tooling on this host."""
        wg_quick = shutil.which("wg-quick")
        wg = shutil.which("wg")
        wireguard_exe = self._find_windows_wireguard() if self._platform == "windows" else None
        available = bool(wg_quick or wireguard_exe)
        return {
            "platform": self._platform,
            "available": available,
            "wg_quick": wg_quick,
            "wg": wg,
            "wireguard_exe": wireguard_exe,
            "hint": None if available else WG_INSTALL_HINT,
        }

    def install_command(self) -> Optional[List[str]]:
        """Return the preferred package-manager install command for this OS, or None."""
        if self._platform == "windows":
            winget = self._find_winget()
            if winget:
                return [
                    winget,
                    "install",
                    "--id",
                    "WireGuard.WireGuard",
                    "-e",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ]
            # Fallback: open official MSI download page guidance
            return None

        if self._platform == "darwin":
            brew = shutil.which("brew")
            if brew:
                return [brew, "install", "wireguard-tools"]
            return None

        # Linux: prefer apt, then dnf/yum, pacman, zypper
        if shutil.which("apt-get"):
            return ["sudo", "apt-get", "install", "-y", "wireguard", "wireguard-tools"]
        if shutil.which("dnf"):
            return ["sudo", "dnf", "install", "-y", "wireguard-tools"]
        if shutil.which("yum"):
            return ["sudo", "yum", "install", "-y", "wireguard-tools"]
        if shutil.which("pacman"):
            return ["sudo", "pacman", "-S", "--noconfirm", "wireguard-tools"]
        if shutil.which("zypper"):
            return ["sudo", "zypper", "install", "-y", "wireguard-tools"]
        return None

    def install_help_lines(self) -> List[str]:
        """Human-readable install instructions for the current platform."""
        lines: List[str] = [
            "WireGuard is required for room tunnels.",
            "Docs: https://www.wireguard.com/install/",
        ]
        cmd = self.install_command()
        if self._platform == "windows":
            if cmd:
                lines.append(
                    "Install (PowerShell / CMD): "
                    "winget install --id WireGuard.WireGuard -e "
                    "--accept-package-agreements --accept-source-agreements"
                )
            else:
                lines.append(
                    "Install: download the Windows installer from "
                    "https://www.wireguard.com/install/ then run it."
                )
            lines.append("Or in KittySploit:  room install-wg")
            lines.append("Then restart the console and run:  room connect --token ...")
            return lines

        if self._platform == "darwin":
            if cmd:
                lines.append("Install (Terminal):  brew install wireguard-tools")
            else:
                lines.append(
                    "Install Homebrew first (https://brew.sh), then: "
                    "brew install wireguard-tools"
                )
                lines.append(
                    "Or download the macOS app from https://www.wireguard.com/install/"
                )
            lines.append("Or in KittySploit:  room install-wg")
            return lines

        # Linux
        if cmd:
            # Show a clean copy-paste command (sudo apt-get ... etc.)
            display = " ".join(cmd)
            lines.append(f"Install (shell):  {display}")
        else:
            lines.append(
                "Install with your package manager, e.g.: "
                "sudo apt install wireguard wireguard-tools"
            )
        lines.append("Or in KittySploit:  room install-wg")
        return lines

    def _find_winget(self) -> Optional[str]:
        which = shutil.which("winget")
        if which:
            return which
        candidates = [
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Microsoft"
            / "WindowsApps"
            / "winget.exe",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "WindowsApps"
            / "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
            / "winget.exe",
        ]
        for path in candidates:
            if path.is_file():
                return str(path)
        return None

    def ensure_installed(
        self,
        ask_confirmation: bool = True,
        auto_yes: bool = False,
    ) -> bool:
        """Ensure WireGuard tooling is present; optionally prompt and install."""
        if self.detect()["available"]:
            return True

        cmd = self.install_command()
        print_warning("WireGuard is not installed (required for room tunnels).")
        for line in self.install_help_lines():
            print_info(line)

        if not cmd:
            return False

        if auto_yes:
            proceed = True
        elif ask_confirmation:
            print_info("Install WireGuard now? [y/N]: ", end="")
            try:
                response = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                print_warning("\nInstallation cancelled.")
                return False
            proceed = response in ("y", "yes")
        else:
            return False

        if not proceed:
            print_warning("WireGuard installation skipped.")
            return False

        return self.install()

    def install(self) -> bool:
        """Run the platform package-manager install for WireGuard."""
        cmd = self.install_command()
        if not cmd:
            print_error(f"Cannot auto-install on this system. {WG_INSTALL_HINT}")
            return False

        print_info(f"Installing WireGuard: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=WG_INSTALL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            print_error("WireGuard install timed out.")
            return False
        except OSError as exc:
            print_error(f"WireGuard install failed to start: {exc}")
            return False

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            print_error(f"WireGuard install failed: {err or result.returncode}")
            print_info(WG_INSTALL_HINT)
            return False

        # winget may succeed while PATH / detection still needs a moment
        if self.detect()["available"]:
            print_success("WireGuard installed.")
            return True

        # Windows: binary is usually under Program Files even if PATH not refreshed
        if self._platform == "windows" and self._find_windows_wireguard():
            print_success("WireGuard installed.")
            return True

        print_warning(
            "Installer finished, but WireGuard tools are not detectable yet. "
            "Restart the terminal (or reboot on Windows) and re-run room connect."
        )
        print_info(WG_INSTALL_HINT)
        return False

    def conf_path(self) -> Path:
        if self._platform == "windows":
            return self.conf_dir / f"{WINDOWS_TUNNEL_NAME}.conf"
        return self.conf_dir / f"{self.interface_name}.conf"

    def write_conf(self, peer: WireGuardPeerConfig, dry_run: bool = False) -> Path:
        text = peer.to_wg_quick_conf(self.interface_name)
        path = self.conf_path()
        if dry_run:
            print_info(f"[dry-run] Would write WireGuard config -> {path}")
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self._active_conf = path
        return path

    def up(
        self,
        peer: WireGuardPeerConfig,
        dry_run: bool = False,
        verify_url: Optional[str] = None,
        verify_timeout: float = 15.0,
        offer_install: bool = True,
        auto_install: bool = False,
    ) -> bool:
        detection = self.detect()
        if dry_run:
            path = self.write_conf(peer, dry_run=False)
            print_info(f"[dry-run] Wrote config (tunnel not activated): {path}")
            if not detection["available"]:
                cmd = self.install_command()
                print_warning(f"WireGuard not installed yet. {WG_INSTALL_HINT}")
                if cmd:
                    print_info(f"Would offer: {' '.join(cmd)}")
            return True

        if not detection["available"]:
            if offer_install or auto_install:
                if not self.ensure_installed(
                    ask_confirmation=not auto_install,
                    auto_yes=auto_install,
                ):
                    return False
                detection = self.detect()
            if not detection["available"]:
                print_error(f"WireGuard not found. {WG_INSTALL_HINT}")
                return False

        path = self.write_conf(peer, dry_run=False)

        print_info(f"Activating WireGuard tunnel ({self._platform})...")
        try:
            if self._platform == "windows":
                ok = self._up_windows(path)
            else:
                ok = self._up_unix(path, detection.get("wg_quick"))
        except Exception as exc:
            print_error(f"Tunnel activation failed: {exc}")
            return False

        if not ok:
            return False

        print_success(f"Tunnel up - split route {', '.join(peer.allowed_ips)}")
        if verify_url:
            if not self.verify_reachability(verify_url, timeout=verify_timeout):
                print_warning(
                    f"Tunnel is up but target not reachable yet: {verify_url} "
                    "(DNS/WG handshake may still be settling)"
                )
        return True

    def down(self, dry_run: bool = False) -> bool:
        path = self._active_conf or self.conf_path()
        if dry_run:
            print_info(f"[dry-run] Would bring down tunnel for {path}")
            return True

        detection = self.detect()
        try:
            if self._platform == "windows":
                ok = self._down_windows(path)
            else:
                ok = self._down_unix(path, detection.get("wg_quick"))
        except Exception as exc:
            print_error(f"Tunnel teardown failed: {exc}")
            return False

        if ok:
            print_success("Room tunnel disconnected")
            self._active_conf = None
        return ok

    def status(self) -> Dict[str, Any]:
        detection = self.detect()
        conf = self.conf_path()
        active = False
        detail = ""
        if self._platform == "windows":
            active, detail = self._windows_tunnel_active()
        elif detection.get("wg"):
            try:
                result = subprocess.run(
                    [detection["wg"], "show", self.interface_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                active = result.returncode == 0
                detail = (result.stdout or result.stderr or "").strip()[:500]
            except (OSError, subprocess.SubprocessError) as exc:
                detail = str(exc)
        return {
            "platform": self._platform,
            "available": detection["available"],
            "conf_path": str(conf),
            "conf_exists": conf.is_file(),
            "active": active,
            "detail": detail,
            "hint": detection.get("hint"),
        }

    def verify_reachability(self, url: str, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        last_err = ""
        while time.time() < deadline:
            try:
                req = Request(url, method="HEAD")
                with urlopen(req, timeout=5) as resp:
                    if 200 <= getattr(resp, "status", 200) < 500:
                        print_success(f"Target reachable: {url}")
                        return True
            except HTTPError as exc:
                # Lab may answer 401/403/404 — still proves L3/L4 reachability
                if exc.code < 500:
                    print_success(f"Target reachable: {url} (HTTP {exc.code})")
                    return True
                last_err = str(exc)
            except (URLError, OSError, ValueError) as exc:
                last_err = str(exc)
            # Fallback GET if HEAD not allowed
            try:
                req = Request(url, method="GET")
                with urlopen(req, timeout=5) as resp:
                    if 200 <= getattr(resp, "status", 200) < 500:
                        print_success(f"Target reachable: {url}")
                        return True
            except HTTPError as exc:
                if exc.code < 500:
                    print_success(f"Target reachable: {url} (HTTP {exc.code})")
                    return True
                last_err = str(exc)
            except (URLError, OSError, ValueError) as exc:
                last_err = str(exc)
            time.sleep(1.0)
        if last_err:
            print_warning(f"Reachability check failed: {last_err}")
        return False

    # --- platform helpers -------------------------------------------------

    def _find_windows_wireguard(self) -> Optional[str]:
        which = shutil.which("wireguard")
        if which:
            return which
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "WireGuard"
            / "wireguard.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "WireGuard"
            / "wireguard.exe",
        ]
        for path in candidates:
            if path.is_file():
                return str(path)
        return None

    def _run(
        self, cmd: List[str], check: bool = False
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=check,
        )

    def _up_unix(self, conf_path: Path, wg_quick: Optional[str]) -> bool:
        if not wg_quick:
            print_error(f"wg-quick not found. {WG_INSTALL_HINT}")
            return False
        # Prefer bringing down stale interface first
        self._down_unix(conf_path, wg_quick, quiet=True)
        result = self._run([wg_quick, "up", str(conf_path)])
        if result.returncode != 0:
            # Retry with sudo (common on Linux without CAP_NET_ADMIN)
            sudo = shutil.which("sudo")
            if sudo:
                print_info("Retrying with sudo (network privilege required)...")
                result = self._run([sudo, wg_quick, "up", str(conf_path)])
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "").strip()
                print_error(f"wg-quick up failed: {err or result.returncode}")
                return False
        return True

    def _down_unix(
        self, conf_path: Path, wg_quick: Optional[str], quiet: bool = False
    ) -> bool:
        if not wg_quick:
            if not quiet:
                print_error(f"wg-quick not found. {WG_INSTALL_HINT}")
            return False
        if not conf_path.is_file() and not quiet:
            # Still try by interface name
            result = self._run([wg_quick, "down", self.interface_name])
        else:
            result = self._run([wg_quick, "down", str(conf_path)])
        if result.returncode != 0:
            sudo = shutil.which("sudo")
            if sudo:
                result = self._run([sudo, wg_quick, "down", str(conf_path)])
            if result.returncode != 0:
                if not quiet:
                    err = (result.stderr or result.stdout or "").strip()
                    print_warning(f"wg-quick down: {err or result.returncode}")
                return False
        return True

    def _up_windows(self, conf_path: Path) -> bool:
        exe = self._find_windows_wireguard()
        if not exe:
            print_error(f"wireguard.exe not found. {WG_INSTALL_HINT}")
            return False
        self._down_windows(conf_path, quiet=True)
        # Official CLI: wireguard /installtunnelservice <conf>
        result = self._run([exe, "/installtunnelservice", str(conf_path)])
        if result.returncode == 0:
            return True

        err = (result.stderr or result.stdout or "").strip()
        denied = "denied" in err.lower() or result.returncode in (5, 740)
        if denied:
            print_warning("Access denied — WireGuard needs administrator rights.")
            print_info("Requesting UAC elevation (accept the Windows prompt)...")
            if self._up_windows_elevated(exe, conf_path):
                return True
            print_error("Elevated WireGuard install failed or UAC was cancelled.")
            print_info("Fix: restart KittySploit as Administrator, then retry room connect.")
            print_info(f"Or import this config in the WireGuard app: {conf_path}")
            return False

        print_error(
            f"WireGuard tunnel install failed: {err or result.returncode}"
        )
        print_info(f"Config saved at: {conf_path}")
        return False

    def _up_windows_elevated(self, exe: str, conf_path: Path) -> bool:
        """Re-run installtunnelservice via UAC (Start-Process -Verb RunAs)."""
        # Escape for PowerShell single-quoted strings
        exe_ps = str(exe).replace("'", "''")
        conf_ps = str(conf_path).replace("'", "''")
        ps = (
            f"$p = Start-Process -FilePath '{exe_ps}' "
            f"-ArgumentList @('/installtunnelservice','{conf_ps}') "
            f"-Verb RunAs -Wait -PassThru; exit $p.ExitCode"
        )
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    ps,
                ],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            print_error(f"UAC elevation failed: {exc}")
            return False

        if result.returncode == 0:
            print_success("WireGuard tunnel installed (elevated).")
            return True

        # Confirm via service query — UAC child exit codes can be unreliable
        active, _ = self._windows_tunnel_active()
        if active:
            print_success("WireGuard tunnel is running.")
            return True

        err = (result.stderr or result.stdout or "").strip()
        if err:
            print_warning(f"Elevated install: {err}")
        return False

    def _down_windows(self, conf_path: Path, quiet: bool = False) -> bool:
        exe = self._find_windows_wireguard()
        if not exe:
            if not quiet:
                print_error(f"wireguard.exe not found. {WG_INSTALL_HINT}")
            return False
        # Prefer uninstall by tunnel name
        result = self._run([exe, "/uninstalltunnelservice", WINDOWS_TUNNEL_NAME])
        if result.returncode != 0 and "denied" in (
            (result.stderr or result.stdout or "") + ""
        ).lower():
            exe_ps = str(exe).replace("'", "''")
            ps = (
                f"$p = Start-Process -FilePath '{exe_ps}' "
                f"-ArgumentList @('/uninstalltunnelservice','{WINDOWS_TUNNEL_NAME}') "
                f"-Verb RunAs -Wait -PassThru; exit $p.ExitCode"
            )
            try:
                result = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        ps,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        if result.returncode != 0 and conf_path.is_file():
            # Fallback: some builds accept conf path
            result = self._run([exe, "/uninstalltunnelservice", str(conf_path)])
        if result.returncode != 0:
            if not quiet:
                err = (result.stderr or result.stdout or "").strip()
                print_warning(f"WireGuard uninstall: {err or result.returncode}")
            return False
        return True

    def _windows_tunnel_active(self) -> Tuple[bool, str]:
        try:
            result = self._run(
                ["sc", "query", f"WireGuardTunnel${WINDOWS_TUNNEL_NAME}"]
            )
            out = (result.stdout or "") + (result.stderr or "")
            active = "RUNNING" in out.upper()
            return active, out.strip()[:500]
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
