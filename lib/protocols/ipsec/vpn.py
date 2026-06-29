#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""strongSwan / libreswan IPsec VPN client helpers (IKEv1 PSK + XAUTH)."""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.framework.base_module import BaseModule
from core.framework.option import OptBool, OptString

DEFAULT_CONN_NAME = "kitty-vpn"
DEFAULT_IKE_PROPOSALS = (
    "3des-sha1-modp1024,3des-md5-modp1024,aes128-sha1-modp2048,aes256-sha1-modp2048"
)
DEFAULT_ESP_PROPOSALS = "3des-sha1,aes128-sha1,aes256-sha1,aes128-sha256,aes256-sha256"

_ASSIGNED_IP_RE = re.compile(
    r"(?:local virtual IP|virtual IP|assigned IP)[^\d]*(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
_TUN_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})/32\b")
_ESTABLISHED_RE = re.compile(r"\bESTABLISHED\b", re.IGNORECASE)


@dataclass
class VpnProfile:
    conn_name: str
    host: str
    port: int
    group_id: str
    psk: str
    username: str
    password: str
    aggressive: bool = True
    nat_t: bool = False
    ike_proposals: str = DEFAULT_IKE_PROPOSALS
    esp_proposals: str = DEFAULT_ESP_PROPOSALS
    route_cidr: str = ""


def _escape_secret(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


class IpsecVpn(BaseModule):
    """Mixin to bring up IKEv1 PSK + XAUTH tunnels via strongSwan stroke (`ipsec`)."""

    psk = OptString("", "Pre-shared key (Phase 1)", required=True)
    username = OptString("", "XAUTH username", required=True)
    password = OptString("", "XAUTH password", required=True)
    group_id = OptString("", "VPN group name / IKE ID (leftid)", required=True)
    conn_name = OptString(DEFAULT_CONN_NAME, "strongSwan connection name", required=False, advanced=True)
    aggressive = OptBool(True, "Use IKEv1 Aggressive Mode", required=False)
    ike_proposals = OptString(
        DEFAULT_IKE_PROPOSALS,
        "IKE (Phase 1) proposal list for strongSwan",
        required=False,
        advanced=True,
    )
    esp_proposals = OptString(
        DEFAULT_ESP_PROPOSALS,
        "ESP (Phase 2) proposal list for strongSwan",
        required=False,
        advanced=True,
    )
    route_cidr = OptString(
        "",
        "Optional CIDR to route through the tunnel after connect (e.g. 10.10.10.0/24)",
        required=False,
    )
    keep_config = OptBool(
        False,
        "Keep generated ipsec.conf / ipsec.secrets in work_dir instead of deleting",
        required=False,
        advanced=True,
    )
    work_dir = OptString(
        "",
        "Directory for generated strongSwan configs (empty = temp dir)",
        required=False,
        advanced=True,
    )
    ipsec_binary = OptString(
        "",
        "Path to ipsec/strongSwan stroke binary (empty = auto-detect)",
        required=False,
        advanced=True,
    )

    def _vpn_ipsec_bin(self) -> str:
        custom = str(getattr(self.ipsec_binary, "value", None) or self.ipsec_binary or "").strip()
        if custom:
            return custom
        for candidate in ("ipsec", "/usr/sbin/ipsec", "/sbin/ipsec"):
            path = shutil.which(candidate) if not candidate.startswith("/") else candidate
            if path and os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return ""

    def _vpn_profile(self) -> Optional[VpnProfile]:
        host = self._ike_host() if hasattr(self, "_ike_host") else ""
        if not host:
            host = str(getattr(self.target, "value", None) or getattr(self, "target", "") or "").strip()
            try:
                host = socket.gethostbyname(host) if host else ""
            except OSError:
                pass
        if not host:
            return None

        port = int(getattr(self, "_ike_port", lambda: 500)())
        group_id = str(getattr(self.group_id, "value", None) or self.group_id or "").strip()
        psk = str(getattr(self.psk, "value", None) or self.psk or "")
        username = str(getattr(self.username, "value", None) or self.username or "")
        password = str(getattr(self.password, "value", None) or self.password or "")
        if not group_id or not psk or not username:
            return None

        nat_t = bool(getattr(self, "_ike_nat_t", lambda: False)())
        gid = group_id if group_id.startswith("@") else f"@{group_id}"

        return VpnProfile(
            conn_name=str(getattr(self.conn_name, "value", None) or self.conn_name or DEFAULT_CONN_NAME),
            host=host,
            port=port,
            group_id=gid,
            psk=psk,
            username=username,
            password=password,
            aggressive=bool(getattr(self.aggressive, "value", self.aggressive)),
            nat_t=nat_t or port == 4500,
            ike_proposals=str(
                getattr(self.ike_proposals, "value", None) or self.ike_proposals or DEFAULT_IKE_PROPOSALS
            ),
            esp_proposals=str(
                getattr(self.esp_proposals, "value", None) or self.esp_proposals or DEFAULT_ESP_PROPOSALS
            ),
            route_cidr=str(getattr(self.route_cidr, "value", None) or self.route_cidr or "").strip(),
        )

    @staticmethod
    def vpn_render_ipsec_conf(profile: VpnProfile) -> str:
        lines = [
            "config setup",
            "    charondebug=ike 1,cfg 1,knl 1",
            "",
            f"conn {profile.conn_name}",
            "    keyexchange=ikev1",
            f"    ike={profile.ike_proposals}",
            f"    esp={profile.esp_proposals}",
            "    authby=xauthpsk",
            "    left=%defaultroute",
            f"    leftid={profile.group_id}",
            "    leftauth=psk",
            "    leftauth2=xauth",
            f"    leftusername={profile.username}",
            f"    right={profile.host}",
            "    rightid=%any",
            "    rightauth=psk",
            "    xauth=client",
            "    type=tunnel",
            "    auto=add",
            "    dpddelay=30",
            "    dpdtimeout=120",
            "    dpdaction=restart",
            "    installpolicy=yes",
        ]
        if profile.aggressive:
            lines.append("    aggressive=yes")
        if profile.nat_t:
            lines.extend(
                [
                    "    forceencaps=yes",
                    "    fragmentation=yes",
                ]
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def vpn_render_ipsec_secrets(profile: VpnProfile) -> str:
        psk = _escape_secret(profile.psk)
        password = _escape_secret(profile.password)
        user = profile.username
        return (
            f': PSK "{psk}"\n'
            f'{user} : XAUTH "{password}"\n'
        )

    def vpn_write_configs(self, profile: VpnProfile, directory: Path) -> Tuple[Path, Path]:
        directory.mkdir(parents=True, exist_ok=True)
        conf_path = directory / "ipsec.conf"
        secrets_path = directory / "ipsec.secrets"
        conf_path.write_text(self.vpn_render_ipsec_conf(profile), encoding="utf-8")
        secrets_path.write_text(self.vpn_render_ipsec_secrets(profile), encoding="utf-8")
        try:
            os.chmod(secrets_path, 0o600)
        except OSError:
            pass
        return conf_path, secrets_path

    def _vpn_run(
        self,
        ipsec_bin: str,
        conf_path: Path,
        secrets_path: Path,
        args: List[str],
        timeout: float = 60.0,
    ) -> subprocess.CompletedProcess:
        cmd = [
            ipsec_bin,
            "--config",
            str(conf_path),
            "--secrets",
            str(secrets_path),
            *args,
        ]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    @staticmethod
    def vpn_parse_status(output: str) -> Dict[str, str]:
        info: Dict[str, str] = {}
        if _ESTABLISHED_RE.search(output or ""):
            info["state"] = "ESTABLISHED"
        for pattern in (_ASSIGNED_IP_RE, _TUN_IP_RE):
            match = pattern.search(output or "")
            if match:
                info["virtual_ip"] = match.group(1)
                break
        return info

    def vpn_add_route(self, cidr: str, dev: str = "") -> Tuple[bool, str]:
        if not cidr:
            return False, "No route CIDR specified"
        route_bin = shutil.which("ip") or "/sbin/ip"
        if not route_bin:
            return False, "iproute2 `ip` binary not found"
        cmd = [route_bin, "route", "add", cidr]
        if dev:
            cmd.extend(["dev", dev])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return False, str(exc)
        if proc.returncode == 0:
            return True, f"Route added: {cidr}"
        if "File exists" in (proc.stderr or proc.stdout or ""):
            return True, f"Route already present: {cidr}"
        return False, (proc.stderr or proc.stdout or "route add failed").strip()

    def vpn_connect(self) -> Dict[str, object]:
        """Write configs, start strongSwan stroke, and bring up the tunnel."""
        profile = self._vpn_profile()
        if not profile:
            return {"status": "error", "reason": "Missing target, group_id, psk, or username"}

        ipsec_bin = self._vpn_ipsec_bin()
        if not ipsec_bin:
            return {
                "status": "error",
                "reason": "strongSwan/libreswan `ipsec` binary not found (install strongswan-starter)",
            }

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return {
                "status": "error",
                "reason": "IPsec tunnel setup requires root (sudo); stroke manipulates kernel XFRM policy",
            }

        work_dir_opt = str(getattr(self.work_dir, "value", None) or self.work_dir or "").strip()
        if work_dir_opt:
            work_path = Path(work_dir_opt)
        else:
            work_path = Path(tempfile.mkdtemp(prefix="kitty-ipsec-"))

        conf_path, secrets_path = self.vpn_write_configs(profile, work_path)
        logs: List[str] = []

        try:
            for step_args, label in (
                (["start", "--nofork"], "start"),
                (["add", profile.conn_name], "add"),
                (["up", profile.conn_name], "up"),
            ):
                proc = self._vpn_run(ipsec_bin, conf_path, secrets_path, step_args, timeout=90.0)
                chunk = (proc.stdout or "") + (proc.stderr or "")
                if chunk.strip():
                    logs.append(f"[{label}]\n{chunk.strip()}")
                if proc.returncode != 0 and label != "start":
                    if not work_dir_opt:
                        shutil.rmtree(work_path, ignore_errors=True)
                    return {
                        "status": "failed",
                        "reason": f"ipsec {label} failed (exit {proc.returncode})",
                        "logs": "\n\n".join(logs),
                        "work_dir": str(work_path),
                        "profile": profile,
                    }

            status_proc = self._vpn_run(
                ipsec_bin,
                conf_path,
                secrets_path,
                ["statusall", profile.conn_name],
                timeout=30.0,
            )
            status_out = (status_proc.stdout or "") + (status_proc.stderr or "")
            if status_out.strip():
                logs.append(f"[statusall]\n{status_out.strip()}")

            parsed = self.vpn_parse_status(status_out)
            if parsed.get("state") != "ESTABLISHED":
                if not work_dir_opt:
                    shutil.rmtree(work_path, ignore_errors=True)
                return {
                    "status": "failed",
                    "reason": "Tunnel did not reach ESTABLISHED — check group ID, PSK, or XAUTH credentials",
                    "logs": "\n\n".join(logs),
                    "work_dir": str(work_path),
                    "profile": profile,
                }

            route_msg = ""
            if profile.route_cidr:
                ok, route_msg = self.vpn_add_route(profile.route_cidr)
                if ok:
                    logs.append(f"[route] {route_msg}")
                else:
                    logs.append(f"[route] failed: {route_msg}")

            return {
                "status": "connected",
                "reason": "IPsec VPN tunnel established",
                "virtual_ip": parsed.get("virtual_ip", ""),
                "logs": "\n\n".join(logs),
                "work_dir": str(work_path),
                "profile": profile,
                "route": route_msg,
                "disconnect_hint": (
                    f"sudo {ipsec_bin} --config {conf_path} --secrets {secrets_path} "
                    f"down {profile.conn_name}; "
                    f"sudo {ipsec_bin} --config {conf_path} stop"
                ),
            }
        except Exception:
            if not work_dir_opt:
                shutil.rmtree(work_path, ignore_errors=True)
            raise

    def vpn_disconnect(self, work_dir: Optional[str] = None, conn_name: Optional[str] = None) -> Dict[str, object]:
        profile = self._vpn_profile()
        ipsec_bin = self._vpn_ipsec_bin()
        if not ipsec_bin or not profile:
            return {"status": "error", "reason": "Cannot resolve ipsec binary or profile"}

        directory = Path(work_dir or str(getattr(self.work_dir, "value", None) or self.work_dir or ""))
        if not directory.is_dir():
            return {"status": "error", "reason": f"work_dir not found: {directory}"}

        conf_path = directory / "ipsec.conf"
        secrets_path = directory / "ipsec.secrets"
        name = conn_name or profile.conn_name
        logs = []
        for args in (["down", name], ["stop"]):
            proc = self._vpn_run(ipsec_bin, conf_path, secrets_path, args, timeout=30.0)
            chunk = (proc.stdout or "") + (proc.stderr or "")
            if chunk.strip():
                logs.append(chunk.strip())
        return {"status": "disconnected", "logs": "\n".join(logs)}
