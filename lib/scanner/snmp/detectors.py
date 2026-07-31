#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNMP Cisco IOS / Windows recon (NSE snmp-ios-config / snmp-win32-users)."""

from __future__ import annotations

from typing import Dict, List


def probe_snmp_ios_config(
    host: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """
    Fingerprint Cisco IOS via SNMP and collect config-related MIB hints.
    Full TFTP config-copy (NSE default) is optional via presence of copy MIB only —
    this probe stays non-destructive (read OIDs).
    """
    result: Dict[str, object] = {
        "detected": False,
        "cisco": False,
        "sysdescr": "",
        "sysname": "",
        "ios_image": "",
        "config_copy_mib": False,
        "running_last_changed": "",
        "error": "",
    }
    try:
        from lib.protocols.snmp.snmp_client import SNMPClient
    except Exception as exc:
        result["error"] = f"snmp_unavailable:{exc}"
        return result

    try:
        client = SNMPClient(
            host=host,
            port=int(port),
            community=str(community),
            version=SNMPClient.V2C,
            timeout=int(timeout),
        )
        sysdescr = client.get(SNMPClient.OIDS["system_description"])
        if not sysdescr:
            result["error"] = "no_sysdescr"
            return result
        result["detected"] = True
        result["sysdescr"] = str(sysdescr)[:300]
        low = str(sysdescr).lower()
        result["cisco"] = "cisco" in low or "ios" in low

        sysname = client.get(SNMPClient.OIDS["system_name"])
        if sysname:
            result["sysname"] = str(sysname)[:120]

        # ciscoImageString / OLD-CISCO-SYSTEM-MIB variants
        for oid in (
            "1.3.6.1.4.1.9.2.1.73.0",
            "1.3.6.1.4.1.9.9.25.1.1.1.2.5",
            "1.3.6.1.4.1.9.9.25.1.1.1.2.6",
        ):
            val = client.get(oid)
            if val and str(val) not in ("No Such Object currently exists at this OID", "None"):
                result["ios_image"] = str(val)[:200]
                result["cisco"] = True
                break

        # CISCO-CONFIG-COPY-MIB presence (ccCopyTable)
        copy_hint = client.get("1.3.6.1.4.1.9.9.96.1.1.1.1.2.1")
        if copy_hint is not None and str(copy_hint) not in (
            "No Such Object currently exists at this OID",
            "None",
        ):
            result["config_copy_mib"] = True
            result["cisco"] = True

        # ccmHistoryRunningLastChanged
        changed = client.get("1.3.6.1.4.1.9.9.43.1.1.1.0")
        if changed:
            result["running_last_changed"] = str(changed)[:80]
            result["cisco"] = True

        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


def probe_snmp_win32_users(
    host: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 5.0,
    max_users: int = 40,
) -> Dict[str, object]:
    """Enumerate Windows local users via LANMANAGER-MIB (NSE snmp-win32-users)."""
    result: Dict[str, object] = {
        "detected": False,
        "users": [],
        "error": "",
    }
    try:
        from lib.protocols.snmp.snmp_client import SNMPClient
    except Exception as exc:
        result["error"] = f"snmp_unavailable:{exc}"
        return result

    # LANMAN-MIB svUserTable
    base = "1.3.6.1.4.1.77.1.2.25"
    try:
        client = SNMPClient(
            host=host,
            port=int(port),
            community=str(community),
            version=SNMPClient.V2C,
            timeout=int(timeout),
        )
        users: List[str] = []
        walked = client.walk(base, max_results=max_users * 3) if hasattr(client, "walk") else {}
        if isinstance(walked, dict):
            for oid_s, val in walked.items():
                text = str(val).strip()
                if text and text not in ("None", "") and not text.startswith("1.3.6"):
                    users.append(text[:64])
                    continue
                suffix = str(oid_s)[len(base) :].lstrip(".")
                parts = [p for p in suffix.split(".") if p.isdigit()]
                chars = []
                for p in parts[1:]:
                    n = int(p)
                    if 32 <= n < 127:
                        chars.append(chr(n))
                name = "".join(chars).strip()
                if name:
                    users.append(name[:64])
        if not users:
            for i in range(1, 16):
                val = client.get(f"{base}.1.1.{i}")
                if val and str(val) not in ("None", ""):
                    users.append(str(val)[:64])
        seen = set()
        uniq = []
        for u in users:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        users = uniq[:max_users]
        result["users"] = users
        result["detected"] = bool(users)
        if not users:
            result["error"] = "no_users"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
