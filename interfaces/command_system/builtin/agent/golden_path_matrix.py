#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deterministic service → detection → validation → access paths for lab missions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence


@dataclass(frozen=True)
class GoldenPathStep:
    stage: str
    module_path: str
    capability_out: str = ""
    recovery_alternate: str = ""


@dataclass(frozen=True)
class GoldenPath:
    id: str
    service: str
    os: str
    description: str
    steps: Sequence[GoldenPathStep]
    tags: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "service": self.service,
            "os": self.os,
            "description": self.description,
            "tags": list(self.tags),
            "steps": [
                {
                    "stage": step.stage,
                    "module_path": step.module_path,
                    "capability_out": step.capability_out,
                    "recovery_alternate": step.recovery_alternate,
                }
                for step in self.steps
            ],
        }


GOLDEN_PATH_MATRIX: Dict[str, GoldenPath] = {
    "linux-http-recon": GoldenPath(
        id="linux-http-recon",
        service="http",
        os="linux",
        description="HTTP surface discovery and header intelligence on Linux lab targets.",
        tags=("http", "recon"),
        steps=(
            GoldenPathStep("detect", "auxiliary/scanner/http/crawler", capability_out="endpoints"),
            GoldenPathStep(
                "validate",
                "scanner/http/security_headers_detect",
                capability_out="tech_hints",
            ),
            GoldenPathStep(
                "recover",
                "auxiliary/scanner/http/crawler",
                recovery_alternate="auxiliary/scanner/http/crawler",
            ),
        ),
    ),
    "linux-ssh-access": GoldenPath(
        id="linux-ssh-access",
        service="ssh",
        os="linux",
        description="SSH banner discovery followed by service reachability validation.",
        tags=("ssh", "session"),
        steps=(
            GoldenPathStep(
                "detect",
                "scanner/ssh/openssh_banner_detect",
                capability_out="service_identified",
            ),
            GoldenPathStep(
                "validate",
                "auxiliary/scanner/ssh/ssh_login",
                capability_out="authenticated_session",
                recovery_alternate="auxiliary/scanner/portscan/tcp",
            ),
            GoldenPathStep(
                "recover",
                "auxiliary/scanner/portscan/tcp",
                recovery_alternate="auxiliary/scanner/portscan/tcp",
            ),
        ),
    ),
    "linux-smb-session": GoldenPath(
        id="linux-smb-session",
        service="smb",
        os="linux",
        description="SMB enumeration to explicit session acquisition on lab hosts.",
        tags=("smb", "session"),
        steps=(
            GoldenPathStep(
                "detect",
                "auxiliary/scanner/smb/smb_relay_surface_audit",
                capability_out="service_identified",
            ),
            GoldenPathStep(
                "validate",
                "auxiliary/scanner/smb/share_enum",
                capability_out="share_list",
            ),
            GoldenPathStep(
                "access",
                "auxiliary/scanner/smb/session_acquire",
                capability_out="authenticated_session",
                recovery_alternate="auxiliary/scanner/smb/share_enum",
            ),
        ),
    ),
    "linux-ftp-enum": GoldenPath(
        id="linux-ftp-enum",
        service="ftp",
        os="linux",
        description="FTP banner and anonymous enumeration on Linux lab hosts.",
        tags=("ftp", "recon"),
        steps=(
            GoldenPathStep(
                "detect",
                "scanner/ftp/ftp_banner_detect",
                capability_out="service_identified",
            ),
            GoldenPathStep("validate", "auxiliary/scanner/ftp/ftp_enum", capability_out="unauth_read"),
            GoldenPathStep(
                "recover",
                "auxiliary/scanner/portscan/tcp",
                recovery_alternate="auxiliary/scanner/portscan/tcp",
            ),
        ),
    ),
    "linux-mysql-detect": GoldenPath(
        id="linux-mysql-detect",
        service="mysql",
        os="linux",
        description="MySQL service fingerprinting on database lab targets.",
        tags=("database", "mysql"),
        steps=(
            GoldenPathStep(
                "detect",
                "scanner/mysql/mysql_info_detect",
                capability_out="service_identified",
            ),
            GoldenPathStep(
                "validate",
                "auxiliary/scanner/mysql/mysql_login_bruteforce",
                capability_out="authenticated_session",
                recovery_alternate="auxiliary/scanner/portscan/tcp",
            ),
        ),
    ),
    "linux-tcp-fingerprint": GoldenPath(
        id="linux-tcp-fingerprint",
        service="tcp",
        os="linux",
        description="Generic TCP service discovery for lab readiness.",
        tags=("tcp_service", "recon"),
        steps=(
            GoldenPathStep(
                "detect",
                "auxiliary/scanner/portscan/tcp",
                capability_out="network_service",
            ),
        ),
    ),
    "windows-winrm-access": GoldenPath(
        id="windows-winrm-access",
        service="winrm",
        os="windows",
        description="WinRM discovery and authentication validation on Windows lab images.",
        tags=("winrm", "windows"),
        steps=(
            GoldenPathStep(
                "detect",
                "scanner/tcp/winrm_detect",
                capability_out="service_identified",
            ),
            GoldenPathStep(
                "validate",
                "auxiliary/scanner/tcp/winrm_auth_enum",
                capability_out="authenticated_session",
            ),
            GoldenPathStep(
                "recover",
                "auxiliary/scanner/portscan/tcp",
                recovery_alternate="auxiliary/scanner/portscan/tcp",
            ),
        ),
    ),
}


def list_golden_paths(*, os_name: str = "") -> List[GoldenPath]:
    rows = list(GOLDEN_PATH_MATRIX.values())
    token = str(os_name or "").strip().lower()
    if not token:
        return rows
    return [row for row in rows if row.os.lower() == token]


def golden_path_for_service(service: str, *, os_name: str = "") -> GoldenPath | None:
    service_l = str(service or "").strip().lower()
    os_l = str(os_name or "").strip().lower()
    for row in GOLDEN_PATH_MATRIX.values():
        if row.service.lower() != service_l:
            continue
        if os_l and row.os.lower() != os_l:
            continue
        return row
    return None
