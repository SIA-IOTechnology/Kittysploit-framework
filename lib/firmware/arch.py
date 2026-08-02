#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Detect CPU architecture from firmware blobs (ELF headers) and suggest payloads.

Inherit ``FirmwareArch`` in analysis modules (same pattern as ``FirmwareExtract``):

    class Module(Analysis, FirmwareArch):
        def run(self):
            report = self.analyze_firmware_arch(self.firmware_path)
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from core.framework.base_module import BaseModule

# ELF e_machine values
_EM_386 = 3
_EM_MIPS = 8
_EM_ARM = 40
_EM_X86_64 = 62
_EM_AARCH64 = 183
_EM_RISCV = 243

# EI_DATA
_ELFDATA2LSB = 1
_ELFDATA2MSB = 2


class FirmwareArch(BaseModule):
    """Helpers ELF-arch → payload suggestions for firmware analysis modules."""

    ARCH_PAYLOAD_MAP: Dict[str, List[str]] = {
        "mipsle": [
            "payloads/singles/cmd/mipsle/reverse_tcp",
            "payloads/singles/cmd/unix/busybox_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_http_polling",
            "payloads/singles/cmd/unix/zig_reverse_tcp",
        ],
        "mipsbe": [
            "payloads/singles/cmd/mipsbe/reverse_tcp",
            "payloads/singles/cmd/unix/busybox_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_http_polling",
            "payloads/singles/cmd/unix/zig_reverse_tcp",
        ],
        "mips": [
            "payloads/singles/cmd/mipsle/reverse_tcp",
            "payloads/singles/cmd/mipsbe/reverse_tcp",
            "payloads/singles/cmd/unix/busybox_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_http_polling",
        ],
        "armle": [
            "payloads/singles/cmd/armle/reverse_tcp",
            "payloads/singles/cmd/unix/busybox_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_http_polling",
            "payloads/singles/cmd/unix/zig_reverse_tcp",
        ],
        "armbe": [
            "payloads/singles/cmd/unix/busybox_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_http_polling",
            "payloads/singles/cmd/unix/zig_reverse_tcp",
        ],
        "arm64": [
            "payloads/singles/cmd/unix/busybox_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_http_polling",
            "payloads/singles/cmd/unix/zig_reverse_tcp",
            "payloads/singles/cmd/unix/bash_reverse_tcp",
        ],
        "x86": [
            "payloads/singles/cmd/unix/bash_reverse_tcp",
            "payloads/singles/cmd/unix/python_reverse_tcp",
            "payloads/singles/cmd/unix/zig_reverse_tcp",
        ],
        "x64": [
            "payloads/singles/cmd/unix/bash_reverse_tcp",
            "payloads/singles/cmd/unix/python_reverse_tcp",
            "payloads/singles/cmd/unix/zig_reverse_tcp",
        ],
        "riscv": [
            "payloads/singles/cmd/unix/zig_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_reverse_tcp",
            "payloads/singles/cmd/unix/busybox_http_polling",
        ],
    }

    LISTENER_REVERSE_TCP = "listeners/multi/reverse_tcp"
    LISTENER_ADAPTIVE = "listeners/multi/adaptive_reverse_tcp"
    LISTENER_HTTP_POLLING = "listeners/multi/reverse_http_polling"

    # Payload path substrings that are command-string (not raw shellcode)
    _CMD_PAYLOAD_MARKERS: tuple[str, ...] = (
        "/busybox_",
        "/bash_",
        "/python_",
        "/perl_",
        "/php/",
        "/lua_",
    )

    @classmethod
    def is_cmd_payload(cls, payload_path: str) -> bool:
        path = str(payload_path or "").lower()
        if any(m in path for m in cls._CMD_PAYLOAD_MARKERS):
            return True
        # zig_* may be compiled binary — treat as non-cmd for listener choice
        if "/mipsle/" in path or "/mipsbe/" in path or "/armle/" in path:
            return False
        return "singles/cmd/unix/" in path or "singles/cmd/multi/" in path

    @classmethod
    def pick_listener_for_payload(cls, payload_path: str) -> str:
        """CMD/BusyBox payloads pair with adaptive listener; HTTP polling with reverse_http_polling."""
        path = str(payload_path or "").lower()
        if "http_polling" in path or "busybox_http" in path:
            return cls.LISTENER_HTTP_POLLING
        if cls.is_cmd_payload(payload_path):
            return cls.LISTENER_ADAPTIVE
        return cls.LISTENER_REVERSE_TCP

    @staticmethod
    def _u16(data: bytes, off: int, *, big_endian: bool) -> int:
        return int.from_bytes(data[off : off + 2], "big" if big_endian else "little")

    @classmethod
    def elf_machine_to_arch(cls, e_machine: int, *, big_endian: bool, bits: int = 32) -> str:
        if e_machine == _EM_MIPS:
            return "mipsbe" if big_endian else "mipsle"
        if e_machine == _EM_ARM:
            return "armbe" if big_endian else "armle"
        if e_machine == _EM_AARCH64:
            return "arm64"
        if e_machine == _EM_X86_64:
            return "x64"
        if e_machine == _EM_386:
            return "x86"
        if e_machine == _EM_RISCV:
            return "riscv64" if bits == 64 else "riscv"
        return "unknown"

    @classmethod
    def parse_elf_ident(cls, data: bytes, offset: int = 0) -> Optional[Dict[str, Any]]:
        """Parse ELF e_ident + e_machine at ``offset`` if magic matches."""
        if offset < 0 or offset + 20 > len(data):
            return None
        if data[offset : offset + 4] != b"\x7fELF":
            return None
        ei_class = data[offset + 4]
        ei_data = data[offset + 5]
        if ei_data not in (_ELFDATA2LSB, _ELFDATA2MSB):
            return None
        big = ei_data == _ELFDATA2MSB
        e_machine = cls._u16(data, offset + 18, big_endian=big)
        bits = 64 if ei_class == 2 else 32 if ei_class == 1 else 0
        return {
            "offset": offset,
            "ei_class": ei_class,
            "ei_data": ei_data,
            "endian": "be" if big else "le",
            "bits": bits,
            "e_machine": e_machine,
            "arch": cls.elf_machine_to_arch(e_machine, big_endian=big, bits=bits),
        }

    @classmethod
    def find_elf_headers(cls, data: bytes, *, max_hits: int = 32) -> List[Dict[str, Any]]:
        """Scan buffer for ELF magics and parse architecture metadata."""
        hits: List[Dict[str, Any]] = []
        start = 0
        while len(hits) < max_hits:
            pos = data.find(b"\x7fELF", start)
            if pos < 0:
                break
            parsed = cls.parse_elf_ident(data, pos)
            if parsed and parsed.get("arch") != "unknown":
                hits.append(parsed)
            start = pos + 4
        return hits

    @staticmethod
    def dominant_arch(hits: Iterable[Dict[str, Any]]) -> Optional[str]:
        counts = Counter(
            str(h.get("arch") or "")
            for h in hits
            if h.get("arch") and h.get("arch") != "unknown"
        )
        if not counts:
            return None
        return counts.most_common(1)[0][0]

    @classmethod
    def suggest_payloads_for_arch(cls, arch: str) -> List[str]:
        key = str(arch or "").strip().lower()
        mapping = cls.ARCH_PAYLOAD_MAP
        if key in mapping:
            return list(mapping[key])
        if key.startswith("mips"):
            return list(mapping["mips"])
        if key.startswith("arm") and key != "arm64":
            return list(mapping.get("armle", []))
        return list(mapping.get(key, []))

    @classmethod
    def select_payload_for_arch(
        cls,
        arch: str,
        *,
        preference: str = "auto",
    ) -> Dict[str, Any]:
        """
        Choose primary payload + listener for an architecture.

        preference:
          - auto: embedded (mips/arm*) → BusyBox CMD + adaptive; else first suggestion
          - cmd: prefer BusyBox/bash/python CMD + adaptive
          - raw: prefer mipsle/mipsbe/armle raw reverse_tcp + classic reverse listener
        """
        pref = str(preference or "auto").strip().lower()
        candidates = cls.suggest_payloads_for_arch(arch)
        if not candidates:
            return {
                "arch": arch,
                "primary_payload": "",
                "alternatives": [],
                "listener": cls.LISTENER_ADAPTIVE,
                "preference": pref,
                "reason": "no payload mapped for architecture",
            }

        primary = candidates[0]
        reason = "first mapped payload"
        arch_key = str(arch or "").strip().lower()

        def _first_matching(pred) -> Optional[str]:
            for path in candidates:
                if pred(path):
                    return path
            return None

        if pref == "cmd":
            chosen = _first_matching(cls.is_cmd_payload) or primary
            reason = "CMD preference (BusyBox/bash/python)"
            primary = chosen
        elif pref == "http":
            chosen = _first_matching(lambda p: "http_polling" in p or "busybox_http" in p)
            if chosen:
                primary = chosen
                reason = "HTTP polling preference (embedded C2)"
            else:
                chosen = _first_matching(lambda p: "busybox_reverse_tcp" in p) or primary
                primary = chosen
                reason = "HTTP preference fallback → BusyBox reverse TCP"
        elif pref == "raw":
            chosen = _first_matching(lambda p: not cls.is_cmd_payload(p)) or primary
            reason = "raw shellcode preference"
            primary = chosen
        else:
            # auto
            if arch_key.startswith(("mips", "arm")) and arch_key != "arm64":
                chosen = _first_matching(
                    lambda p: "busybox_reverse_tcp" in p
                ) or _first_matching(cls.is_cmd_payload)
                if chosen:
                    primary = chosen
                    reason = "auto: embedded arch → BusyBox CMD + adaptive listener"
            elif arch_key in {"arm64", "x64", "x86"}:
                chosen = _first_matching(
                    lambda p: "bash_reverse_tcp" in p or "busybox_reverse_tcp" in p
                ) or _first_matching(cls.is_cmd_payload)
                if chosen:
                    primary = chosen
                    reason = "auto: general Linux → CMD shell + adaptive listener"

        listener = cls.pick_listener_for_payload(primary)
        alternatives = [p for p in candidates if p != primary]
        return {
            "arch": arch_key,
            "primary_payload": primary,
            "alternatives": alternatives,
            "listener": listener,
            "preference": pref,
            "payload_kind": "cmd" if cls.is_cmd_payload(primary) else "raw",
            "reason": reason,
        }

    @classmethod
    def build_operator_commands(
        cls,
        plan: Dict[str, Any],
        *,
        lhost: str = "127.0.0.1",
        lport: int = 4444,
    ) -> List[str]:
        """CLI command sequence to stage listener then generate payload."""
        listener = str(plan.get("listener") or cls.LISTENER_ADAPTIVE)
        payload = str(plan.get("primary_payload") or "")
        cmds = [
            f"use {listener}",
            f"set lhost {lhost}",
            f"set lport {int(lport)}",
            "run",
        ]
        if payload:
            cmds.extend(
                [
                    f"use {payload}",
                    f"set lhost {lhost}",
                    f"set lport {int(lport)}",
                    "generate",
                ]
            )
        return cmds

    @classmethod
    def build_adaptive_plan(
        cls,
        report: Dict[str, Any],
        *,
        preference: str = "auto",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
    ) -> Dict[str, Any]:
        """Merge arch analysis with payload/listener selection + operator commands."""
        arch = report.get("primary_arch") or ""
        selection = cls.select_payload_for_arch(str(arch), preference=preference)
        commands = cls.build_operator_commands(selection, lhost=lhost, lport=lport)
        plan = {
            **selection,
            "firmware_path": report.get("firmware_path"),
            "arch_counts": report.get("arch_counts") or {},
            "suggested_payloads": report.get("suggested_payloads") or [],
            "lhost": lhost,
            "lport": int(lport),
            "commands": commands,
        }
        return plan

    @classmethod
    def analyze_firmware_arch(
        cls,
        path: str,
        *,
        scan_mb: int = 8,
        max_hits: int = 32,
        preference: str = "auto",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
    ) -> Dict[str, Any]:
        """Read the start of a firmware image, find ELF headers, suggest payloads."""
        firmware_path = os.path.abspath(str(path).strip())
        if not os.path.isfile(firmware_path):
            raise FileNotFoundError(firmware_path)

        budget = max(1, int(scan_mb)) * 1024 * 1024
        with open(firmware_path, "rb") as handle:
            data = handle.read(budget)

        hits = cls.find_elf_headers(data, max_hits=max_hits)
        primary = cls.dominant_arch(hits)
        suggested = cls.suggest_payloads_for_arch(primary) if primary else []
        if primary and "payloads/singles/cmd/unix/busybox_reverse_tcp" not in suggested:
            if primary.startswith(("mips", "arm")):
                suggested.append("payloads/singles/cmd/unix/busybox_reverse_tcp")
        if primary and primary.startswith(("mips", "arm")):
            http_pl = "payloads/singles/cmd/unix/busybox_http_polling"
            if http_pl not in suggested:
                suggested.append(http_pl)

        arch_counts = Counter(str(h.get("arch")) for h in hits)
        report: Dict[str, Any] = {
            "firmware_path": firmware_path,
            "scanned_bytes": len(data),
            "elf_hits": hits,
            "arch_counts": dict(arch_counts),
            "primary_arch": primary,
            "suggested_payloads": suggested,
            "listener": cls.LISTENER_ADAPTIVE,
        }
        if primary:
            plan = cls.build_adaptive_plan(
                report,
                preference=preference,
                lhost=lhost,
                lport=lport,
            )
            report["adaptive_plan"] = plan
            report["primary_payload"] = plan.get("primary_payload")
            report["listener"] = plan.get("listener") or cls.LISTENER_ADAPTIVE
        return report

    @staticmethod
    def summarize_arch_report(report: Dict[str, Any]) -> List[str]:
        lines: List[str] = []
        primary = report.get("primary_arch")
        if not primary:
            lines.append("No recognizable ELF architecture found in scanned region")
            return lines
        lines.append(f"Primary architecture: {primary}")
        counts = report.get("arch_counts") or {}
        if counts:
            detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            lines.append(f"ELF arch histogram: {detail}")
        plan = report.get("adaptive_plan") if isinstance(report.get("adaptive_plan"), dict) else {}
        if plan.get("primary_payload"):
            lines.append(
                f"Selected payload: {plan['primary_payload']} ({plan.get('payload_kind') or '?'})"
            )
            lines.append(f"Selected listener: {plan.get('listener')}")
            if plan.get("reason"):
                lines.append(f"Reason: {plan['reason']}")
        for payload in report.get("suggested_payloads") or []:
            lines.append(f"Suggested payload: {payload}")
        return lines


# Backward-compatible aliases (prefer inheriting FirmwareArch in modules).
ARCH_PAYLOAD_MAP = FirmwareArch.ARCH_PAYLOAD_MAP
parse_elf_ident = FirmwareArch.parse_elf_ident
elf_machine_to_arch = FirmwareArch.elf_machine_to_arch
find_elf_headers = FirmwareArch.find_elf_headers
dominant_arch = FirmwareArch.dominant_arch
suggest_payloads_for_arch = FirmwareArch.suggest_payloads_for_arch
analyze_firmware_arch = FirmwareArch.analyze_firmware_arch
summarize_arch_report = FirmwareArch.summarize_arch_report
is_cmd_payload = FirmwareArch.is_cmd_payload
pick_listener_for_payload = FirmwareArch.pick_listener_for_payload
select_payload_for_arch = FirmwareArch.select_payload_for_arch
build_adaptive_plan = FirmwareArch.build_adaptive_plan
build_operator_commands = FirmwareArch.build_operator_commands
