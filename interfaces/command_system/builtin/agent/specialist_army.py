#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tactical specialist army — dozens of read-only sub-agents mapped to module families.

Enabled via ``KITTYSPLOIT_AGENT_ARMY=1`` or ``state.specialist_army_enabled``.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from interfaces.command_system.builtin.agent.specialist_registry import SpecialistProfile

DEFAULT_ARMY_FAN_OUT = 12
MAX_ARMY_FAN_OUT = 20


def _p(
    key: str,
    name: str,
    description: str,
    *,
    families: Sequence[str],
    triggers: Sequence[str],
    capabilities: Sequence[str] = (),
    budget: int = 4,
    tactics: Sequence[str] = ("discovery",),
    maturity: str = "stable",
) -> SpecialistProfile:
    return SpecialistProfile(
        key=key,
        name=name,
        description=description[:240],
        capabilities=capabilities or (key, "module_rank"),
        module_families=tuple(families),
        triggers=tuple(triggers),
        inputs=("knowledge_base", "catalog_actions", "campaign_goal"),
        outputs=("specialist_proposal", "hypothesis"),
        budget_requests=budget,
        read_only=True,
        maturity=maturity,
        mitre_tactics=tactics,
    )


def _build_army_profiles() -> Dict[str, SpecialistProfile]:
    rows: Dict[str, SpecialistProfile] = {}

    def add(profile: SpecialistProfile) -> None:
        rows[profile.key] = profile

    # --- Web application corps ---
    for key, name, desc, trigs in (
        ("xxe", "XXE Specialist", "XML external entity and parser differential probes.", ("xxe", "xml", "soap", "svg_upload")),
        ("rce", "RCE Specialist", "Remote code execution chains, gadget paths, and command injection.", ("rce", "command_injection", "ognl", "spring4shell")),
        ("upload", "File Upload Specialist", "Unrestricted upload, extension bypass, and web shell paths.", ("upload", "file_upload", "unrestricted_upload")),
        ("deser", "Deserialization Specialist", "Unsafe deserialization fingerprints and gadget selection.", ("deser", "deserialization", "java_deser", "pickle")),
        ("csrf", "CSRF Specialist", "Cross-site request forgery and state-changing form abuse.", ("csrf", "cross_site")),
        ("cors", "CORS Misconfig Specialist", "Origin reflection, null origin, and credentialed cross-origin reads.", ("cors", "cross_origin")),
        ("cache_poison", "Cache Poison Specialist", "Web cache deception and unkeyed header/cache key abuse.", ("cache", "cache_poison", "web_cache")),
        ("graphql_agent", "GraphQL Specialist", "Introspection, batching, alias overload, and authz on resolvers.", ("graphql", "graphql_surface_detected")),
        ("api_abuse", "REST API Abuse Specialist", "Mass assignment, rate limits, verbose errors, and BOLA on APIs.", ("api", "api_surface_detected", "openapi", "swagger")),
        ("oauth_agent", "OAuth/OIDC Specialist", "Redirect URI abuse, token leakage, and scope confusion.", ("oauth", "oidc", "openid")),
        ("jwt_agent", "JWT Specialist", "Algorithm confusion, weak secrets, and claim tampering.", ("jwt", "jwk", "bearer")),
        ("websocket_agent", "WebSocket Specialist", "Cross-site WebSocket hijacking and origin checks.", ("websocket", "ws://", "wss://")),
        ("tls_agent", "TLS/SSL Specialist", "Weak ciphers, cert issues, and STARTTLS downgrade surfaces.", ("tls", "ssl", "starttls", "443")),
    ):
        add(
            _p(
                key,
                name,
                desc,
                families=("scanner/http", "auxiliary/scanner/http", "exploits/multi/http", "exploits/http"),
                triggers=trigs,
                capabilities=(key.split("_")[0], "validation"),
            )
        )

    # --- CMS / product corps ---
    for key, name, cms_triggers in (
        ("cms_wordpress", "WordPress Specialist", ("wordpress", "wp_", "wp-content", "wp_plugin")),
        ("cms_joomla", "Joomla Specialist", ("joomla", "com_", "sppagebuilder")),
        ("cms_drupal", "Drupal Specialist", ("drupal", "drupalgeddon")),
        ("cms_sharepoint", "SharePoint Specialist", ("sharepoint", "toolshell", "_layouts")),
        ("cms_spring", "Spring/Java Specialist", ("spring", "springboot", "tomcat", "struts")),
        ("cms_php", "PHP Stack Specialist", ("php", "phpmyadmin", "laravel", "symfony")),
    ):
        add(
            _p(
                key,
                name,
                f"{name} CVE and misconfig module selection.",
                families=("scanner/http", "exploits/multi/http", "auxiliary/admin/http"),
                triggers=cms_triggers,
            )
        )

    # --- Network service corps ---
    service_rows = (
        ("ftp_service", "FTP Specialist", ("ftp", "21", "ftps"), ("auxiliary/scanner/ftp", "scanner")),
        ("rdp_service", "RDP/WinRM Specialist", ("rdp", "3389", "winrm", "5985", "5986"), ("auxiliary/scanner/winrm", "scanner")),
        ("dns_service", "DNS Specialist", ("dns", "53", "zone_transfer"), ("auxiliary/scanner/dns", "scanner")),
        ("snmp_service", "SNMP Specialist", ("snmp", "161", "161/udp"), ("scanner/udp", "auxiliary/scanner/snmp")),
        ("redis_service", "Redis Specialist", ("redis", "6379", "unauth_redis"), ("auxiliary/scanner/redis", "scanner")),
        ("mongo_service", "MongoDB Specialist", ("mongodb", "mongo", "27017"), ("auxiliary/scanner/mongodb", "scanner")),
        ("elastic_service", "Elasticsearch Specialist", ("elasticsearch", "elastic", "9200"), ("auxiliary/scanner/elasticsearch", "scanner")),
        ("smtp_service", "SMTP Specialist", ("smtp", "25", "587", "open_relay"), ("auxiliary/scanner/smtp", "scanner")),
        ("vnc_service", "VNC Specialist", ("vnc", "5900"), ("auxiliary/scanner/vnc", "scanner")),
        ("nfs_service", "NFS Specialist", ("nfs", "2049"), ("auxiliary/scanner/nfs", "scanner")),
        ("telnet_service", "Telnet Specialist", ("telnet", "23"), ("auxiliary/scanner/telnet", "scanner")),
        ("docker_service", "Docker/API Specialist", ("docker", "2375", "container", "kube"), ("auxiliary/scanner/docker", "scanner")),
        ("vpn_service", "VPN Specialist", ("vpn", "openvpn", "ipsec", "ike"), ("auxiliary/scanner/vpn", "scanner")),
        ("mikrotik_service", "RouterOS Specialist", ("mikrotik", "routeros", "8291"), ("scanner/tcp", "exploits/linux")),
    )
    for key, name, trigs, families in service_rows:
        add(_p(key, name, f"{name} enumeration and exploit module paths.", families=families, triggers=trigs))

    # --- Cloud / infra corps ---
    for key, name, trigs in (
        ("cloud_aws", "AWS Surface Specialist", ("aws", "s3", "iam", "lambda", "metadata")),
        ("cloud_azure", "Azure Specialist", ("azure", "blob", "managed_identity")),
        ("cloud_k8s", "Kubernetes Specialist", ("kubernetes", "k8s", "etcd", "kubelet")),
        ("cloud_cicd", "CI/CD Specialist", ("jenkins", "gitlab", "github_actions", "circleci")),
    ):
        add(
            _p(
                key,
                name,
                f"{name} misconfig and credential module selection.",
                families=("scanner/http", "auxiliary/scanner/http", "auxiliary/gather"),
                triggers=trigs,
            )
        )

    # --- Identity / AD extended ---
    add(
        _p(
            "kerberos_agent",
            "Kerberos Specialist",
            "Kerberoasting, AS-REP roast, and ticket abuse module paths.",
            families=("auxiliary/scanner/kerberos", "scanner/ldap", "auxiliary/scanner/ldap"),
            triggers=("kerberos", "88", "krbtgt", "asrep"),
            budget=5,
            tactics=("credential-access", "lateral-movement"),
        )
    )
    add(
        _p(
            "ldap_agent",
            "LDAP Specialist",
            "LDAP bind, ACL abuse, and cert template module selection.",
            families=("scanner/ldap", "auxiliary/scanner/ldap"),
            triggers=("ldap", "389", "636", "ldaps"),
            budget=5,
        )
    )

    # --- OSINT / browser ---
    add(
        _p(
            "osint_agent",
            "OSINT Specialist",
            "Passive recon modules, dorks, and credential breach hints.",
            families=("osint", "auxiliary/osint", "auxiliary/gather"),
            triggers=("osint", "recon_passive", "email", "subdomain"),
            budget=3,
            tactics=("reconnaissance",),
        )
    )
    add(
        _p(
            "browser_agent",
            "Browser Automation Specialist",
            "In-browser recon, storage, and client-side attack modules.",
            families=("browser_auxiliary", "auxiliary/browser"),
            triggers=("browser", "dom", "client_side", "xss_confirmed"),
            budget=4,
        )
    )

    # --- OT / ICS (policy-gated via triggers only) ---
    add(
        _p(
            "ics_agent",
            "ICS/OT Specialist",
            "Industrial protocol scanners when OT signals are explicitly in scope.",
            families=("scanner/ics", "auxiliary/scanner/ics", "exploits/ics"),
            triggers=("ics", "modbus", "s7", "dnp3", "ot_scope"),
            budget=3,
            maturity="experimental",
            tactics=("discovery",),
        )
    )

    return rows


ARMY_PROFILES: Dict[str, SpecialistProfile] = _build_army_profiles()

PORT_TRIGGER_MAP: Dict[str, Sequence[str]] = {
    "21": ("ftp_service",),
    "23": ("telnet_service",),
    "25": ("smtp_service",),
    "53": ("dns_service",),
    "88": ("kerberos_agent", "active_directory"),
    "161": ("snmp_service",),
    "389": ("ldap_agent", "active_directory"),
    "636": ("ldap_agent", "active_directory"),
    "443": ("tls_agent", "web_recon"),
    "445": ("smb_service", "active_directory"),
    "3306": ("database_service",),
    "3389": ("rdp_service",),
    "5432": ("database_service",),
    "5900": ("vnc_service",),
    "6379": ("redis_service",),
    "9200": ("elastic_service",),
    "27017": ("mongo_service",),
    "5985": ("rdp_service",),
    "5986": ("rdp_service",),
}


def specialist_army_enabled(state: Any = None, kb: Optional[Mapping[str, Any]] = None) -> bool:
    env = os.environ.get("KITTYSPLOIT_AGENT_ARMY", "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if env in {"1", "true", "yes", "on"}:
        return True
    if state is not None and getattr(state, "specialist_army_enabled", None) is True:
        return True
    if state is not None and getattr(state, "specialist_army_enabled", None) is False:
        return False
    if isinstance(kb, Mapping) and kb.get("specialist_army"):
        return True
    profile = str(getattr(state, "safety_profile", "") or "").strip().lower()
    if profile == "safe":
        return False
    # Army mode defaults ON for normal/aggressive when hierarchical planner is in use.
    return env == "" and profile in {"normal", "aggressive", ""}


def army_fan_out_limit(state: Any = None, kb: Optional[Mapping[str, Any]] = None) -> int:
    if not specialist_army_enabled(state, kb):
        from interfaces.command_system.builtin.agent.specialist_registry import MAX_FAN_OUT

        return MAX_FAN_OUT
    env = os.environ.get("KITTYSPLOIT_AGENT_ARMY_FAN_OUT", "").strip()
    if env.isdigit():
        return max(3, min(int(env), MAX_ARMY_FAN_OUT))
    return DEFAULT_ARMY_FAN_OUT


def _blob(kb: Mapping[str, Any]) -> str:
    parts = [
        " ".join(str(s).lower() for s in (kb.get("identified_services") or kb.get("services") or [])),
        str(kb.get("protocol") or "").lower(),
        " ".join(str(h).lower() for h in (kb.get("tech_hints") or [])),
        " ".join(str(s).lower() for s in (kb.get("risk_signals") or [])),
    ]
    for ep in (kb.get("discovered_endpoints") or [])[:20]:
        parts.append(str(ep).lower())
    return " ".join(parts)


def _trigger_hits(profile: SpecialistProfile, kb: Mapping[str, Any]) -> bool:
    blob = _blob(kb)
    signals = {str(x).lower() for x in (kb.get("risk_signals") or [])}
    hints = {str(x).lower() for x in (kb.get("tech_hints") or [])}
    open_ports = {str(p) for p in (kb.get("open_ports") or [])}

    for trig in profile.triggers:
        t = str(trig or "").lower()
        if not t:
            continue
        if t in signals or t in hints:
            return True
        if t in blob:
            return True
        if t in open_ports:
            return True
        for port, keys in PORT_TRIGGER_MAP.items():
            if port in open_ports and profile.key in keys:
                return True
    return False


def match_army_specialists(
    kb: Mapping[str, Any],
    *,
    phase: str = "",
    army_mode: bool = False,
    limit: int = DEFAULT_ARMY_FAN_OUT,
) -> List[str]:
    """Return specialist keys from the army whose triggers match the KB."""
    kb = kb if isinstance(kb, Mapping) else {}
    phase_l = str(phase or "").lower()
    keys: List[str] = []
    seen: Set[str] = set()

    def _push(key: str) -> None:
        if key in seen or key not in ARMY_PROFILES:
            return
        seen.add(key)
        keys.append(key)

    for key, profile in ARMY_PROFILES.items():
        if _trigger_hits(profile, kb):
            _push(key)

    if army_mode:
        blob = _blob(kb)
        httpish = any(tok in blob for tok in ("http", "https", "web", "api"))
        if httpish and phase_l in {"scan", "analyze", "reason", "act", "plan", ""}:
            for key in ARMY_PROFILES:
                if key.startswith(("cms_", "graphql_", "api_", "oauth_", "jwt_", "xxe", "rce", "upload", "deser")):
                    _push(key)
                elif key in {"csrf", "cors", "cache_poison", "websocket_agent", "tls_agent", "browser_agent"}:
                    _push(key)
        if kb.get("specialist_army_full_web"):
            for key in ARMY_PROFILES:
                if "http" in " ".join(ARMY_PROFILES[key].module_families):
                    _push(key)

    return keys[: max(1, int(limit or DEFAULT_ARMY_FAN_OUT))]


def army_roster_for_llm(*, max_rows: int = 40) -> List[Dict[str, Any]]:
    rows = [p.to_dict() for p in ARMY_PROFILES.values()]
    return rows[:max_rows]


def all_army_keys() -> Sequence[str]:
    return tuple(ARMY_PROFILES.keys())
