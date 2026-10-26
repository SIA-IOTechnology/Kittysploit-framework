#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Domain corps map orchestrator delegation to the tactical specialist army."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, Sequence

DOMAIN_ORCHESTRATOR = "orchestrator"
DOMAIN_WEB = "web"
DOMAIN_SQL = "sql"
DOMAIN_AD = "ad"
DOMAIN_NETWORK = "network"
DOMAIN_POST = "post"
DOMAIN_CLOUD = "cloud"
DOMAIN_CMS = "cms"
DOMAIN_SERVICES = "services"
DOMAIN_OSINT = "osint"
DOMAIN_IDENTITY = "identity"
DOMAIN_OT = "ot"

DOMAIN_AGENT_KEYS: Sequence[str] = (
    DOMAIN_ORCHESTRATOR,
    DOMAIN_WEB,
    DOMAIN_SQL,
    DOMAIN_AD,
    DOMAIN_NETWORK,
    DOMAIN_POST,
    DOMAIN_CLOUD,
    DOMAIN_CMS,
    DOMAIN_SERVICES,
    DOMAIN_OSINT,
    DOMAIN_IDENTITY,
    DOMAIN_OT,
)


@dataclass(frozen=True)
class DomainAgentSpec:
    key: str
    name: str
    description: str
    specialist_keys: FrozenSet[str]
    triggers: FrozenSet[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "specialist_keys": sorted(self.specialist_keys),
            "triggers": sorted(self.triggers),
        }


def _keys(*items: str) -> FrozenSet[str]:
    return frozenset(items)


DOMAIN_AGENTS: Dict[str, DomainAgentSpec] = {
    DOMAIN_ORCHESTRATOR: DomainAgentSpec(
        key=DOMAIN_ORCHESTRATOR,
        name="Mission Orchestrator",
        description="Activates domain corps, merges proposals, enforces RoE and budgets.",
        specialist_keys=_keys("coordinator"),
        triggers=_keys("plan", "reason", "init"),
    ),
    DOMAIN_WEB: DomainAgentSpec(
        key=DOMAIN_WEB,
        name="Web & API Corps",
        description="HTTP/API surface, OWASP-class agents, and browser-side modules.",
        specialist_keys=_keys(
            "web_recon",
            "sqli",
            "xss",
            "lfi",
            "ssrf",
            "ssti",
            "auth",
            "authz",
            "xxe",
            "rce",
            "upload",
            "deser",
            "csrf",
            "cors",
            "cache_poison",
            "graphql_agent",
            "api_abuse",
            "oauth_agent",
            "jwt_agent",
            "websocket_agent",
            "tls_agent",
            "browser_agent",
            "scanner",
        ),
        triggers=_keys(
            "http",
            "https",
            "api",
            "graphql",
            "swagger",
            "login_surface_detected",
            "owasp_web_parallel",
        ),
    ),
    DOMAIN_SQL: DomainAgentSpec(
        key=DOMAIN_SQL,
        name="Database Corps",
        description="SQLi validation and DBMS service modules.",
        specialist_keys=_keys("sqli", "database_service"),
        triggers=_keys("sqli", "sql_signal", "sqli_confirmed", "mysql", "mssql", "postgres", "mariadb", "oracle"),
    ),
    DOMAIN_AD: DomainAgentSpec(
        key=DOMAIN_AD,
        name="Active Directory Corps",
        description="LDAP, Kerberos, SMB domain attack surface.",
        specialist_keys=_keys("active_directory", "smb_service", "ldap_agent", "kerberos_agent"),
        triggers=_keys("ldap", "kerberos", "active_directory", "domain_controller", "adcs", "smb_surface"),
    ),
    DOMAIN_NETWORK: DomainAgentSpec(
        key=DOMAIN_NETWORK,
        name="Network Recon Corps",
        description="Port/service discovery and generic scanners.",
        specialist_keys=_keys("recon", "scanner", "smb_service", "ssh_service", "dns_service", "snmp_service"),
        triggers=_keys("smb", "ssh", "port_scan", "service_detection", "dns"),
    ),
    DOMAIN_SERVICES: DomainAgentSpec(
        key=DOMAIN_SERVICES,
        name="Service Exploit Corps",
        description="Protocol-specific agents (FTP, RDP, Redis, Docker, …).",
        specialist_keys=_keys(
            "ftp_service",
            "rdp_service",
            "redis_service",
            "mongo_service",
            "elastic_service",
            "smtp_service",
            "vnc_service",
            "nfs_service",
            "telnet_service",
            "docker_service",
            "vpn_service",
            "mikrotik_service",
            "ssh_service",
        ),
        triggers=_keys("ftp", "rdp", "redis", "mongodb", "elasticsearch", "docker", "winrm", "telnet"),
    ),
    DOMAIN_CLOUD: DomainAgentSpec(
        key=DOMAIN_CLOUD,
        name="Cloud & CI/CD Corps",
        description="Cloud metadata, K8s, and pipeline misconfig modules.",
        specialist_keys=_keys("cloud_aws", "cloud_azure", "cloud_k8s", "cloud_cicd"),
        triggers=_keys("aws", "azure", "kubernetes", "s3", "jenkins", "gitlab", "metadata"),
    ),
    DOMAIN_CMS: DomainAgentSpec(
        key=DOMAIN_CMS,
        name="CMS & Stack Corps",
        description="WordPress, Joomla, Drupal, SharePoint, Spring/PHP stacks.",
        specialist_keys=_keys(
            "cms_wordpress",
            "cms_joomla",
            "cms_drupal",
            "cms_sharepoint",
            "cms_spring",
            "cms_php",
        ),
        triggers=_keys("wordpress", "joomla", "drupal", "sharepoint", "spring", "php", "wp_plugin"),
    ),
    DOMAIN_OSINT: DomainAgentSpec(
        key=DOMAIN_OSINT,
        name="OSINT Corps",
        description="Passive recon and gather modules.",
        specialist_keys=_keys("osint_agent", "recon"),
        triggers=_keys("osint", "subdomain", "email", "recon_passive"),
    ),
    DOMAIN_IDENTITY: DomainAgentSpec(
        key=DOMAIN_IDENTITY,
        name="Identity Corps",
        description="Auth, JWT, OAuth, and credential-access agents.",
        specialist_keys=_keys("auth", "authz", "jwt_agent", "oauth_agent", "kerberos_agent", "ldap_agent"),
        triggers=_keys("auth", "jwt", "oauth", "credential", "login"),
    ),
    DOMAIN_POST: DomainAgentSpec(
        key=DOMAIN_POST,
        name="Post-Exploitation Corps",
        description="Sessions, lateral movement, collection.",
        specialist_keys=_keys("session_post", "infiltrator", "exfiltrator", "ghost"),
        triggers=_keys("session", "verified_session", "post", "privilege"),
    ),
    DOMAIN_OT: DomainAgentSpec(
        key=DOMAIN_OT,
        name="OT/ICS Corps",
        description="Industrial modules when OT scope is explicit.",
        specialist_keys=_keys("ics_agent"),
        triggers=_keys("ics", "modbus", "ot_scope", "dnp3"),
    ),
}

_SPECIALIST_TO_DOMAIN: Dict[str, str] = {}
for _domain, _spec in DOMAIN_AGENTS.items():
    for _sk in _spec.specialist_keys:
        _SPECIALIST_TO_DOMAIN.setdefault(_sk, _domain)


def domain_for_specialist(specialist_key: str) -> str:
    return _SPECIALIST_TO_DOMAIN.get(str(specialist_key or "").strip().lower(), DOMAIN_NETWORK)


def specialist_keys_for_domains(domains: Sequence[str]) -> List[str]:
    keys: List[str] = []
    seen: set[str] = set()
    for domain in domains:
        spec = DOMAIN_AGENTS.get(str(domain or "").strip().lower())
        if spec is None:
            continue
        for key in spec.specialist_keys:
            if key in seen:
                continue
            seen.add(key)
            keys.append(key)
    return keys


def roster_for_llm() -> List[Dict[str, Any]]:
    rows = [DOMAIN_AGENTS[key].to_dict() for key in DOMAIN_AGENT_KEYS if key != DOMAIN_ORCHESTRATOR]
    try:
        from interfaces.command_system.builtin.agent.specialist_army import army_roster_for_llm

        rows.append({"tactical_army_preview": army_roster_for_llm(max_rows=24)})
    except Exception:
        pass
    return rows


def infer_active_domains(kb: Mapping[str, Any], *, phase: str = "") -> List[str]:
    """Heuristic domain activation from knowledge-base signals (no LLM)."""
    kb = kb if isinstance(kb, Mapping) else {}
    phase_l = str(phase or "").lower()
    signals = {str(item).lower() for item in (kb.get("risk_signals") or [])}
    hints = {str(item).lower() for item in (kb.get("tech_hints") or [])}
    services = " ".join(str(s).lower() for s in (kb.get("identified_services") or kb.get("services") or []))
    protocol = str(kb.get("protocol") or "").lower()
    open_ports = {str(p) for p in (kb.get("open_ports") or [])}
    active: List[str] = []

    def _add(domain: str) -> None:
        if domain not in active:
            active.append(domain)

    httpish = (
        protocol in {"http", "https"}
        or any(tok in services for tok in ("http", "https", "web"))
        or bool(signals.intersection(DOMAIN_AGENTS[DOMAIN_WEB].triggers))
        or bool(kb.get("discovered_endpoints") or kb.get("request_intel"))
    )
    if httpish:
        _add(DOMAIN_WEB)
        _add(DOMAIN_CMS)

    if hints.intersection({"wordpress", "joomla", "drupal", "sharepoint", "spring", "php"}):
        _add(DOMAIN_CMS)

    sqlish = (
        bool(signals.intersection(DOMAIN_AGENTS[DOMAIN_SQL].triggers))
        or bool(kb.get("sql_findings"))
        or "sql" in services
    )
    if sqlish:
        _add(DOMAIN_SQL)

    adish = (
        signals.intersection(DOMAIN_AGENTS[DOMAIN_AD].triggers)
        or hints.intersection({"domain", "ad", "ldap", "kerberos"})
        or open_ports.intersection({"389", "636", "88", "3268", "3269"})
        or "ldap" in services
        or "kerberos" in services
    )
    if adish:
        _add(DOMAIN_AD)
        _add(DOMAIN_IDENTITY)

    if signals.intersection({"jwt", "oauth", "login_surface_detected", "auth"}):
        _add(DOMAIN_IDENTITY)

    netish = (
        protocol in {"smb", "ssh"}
        or "smb" in services
        or "ssh" in services
        or open_ports.intersection({"22", "139", "445"})
    )
    if netish:
        _add(DOMAIN_NETWORK)

    if open_ports.intersection({"21", "23", "25", "3389", "6379", "9200", "27017", "5985"}):
        _add(DOMAIN_SERVICES)

    if hints.intersection({"aws", "azure", "kubernetes", "jenkins"}) or "metadata" in signals:
        _add(DOMAIN_CLOUD)

    if kb.get("osint") or signals.intersection({"osint", "subdomain"}):
        _add(DOMAIN_OSINT)

    if signals.intersection(DOMAIN_AGENTS[DOMAIN_OT].triggers):
        _add(DOMAIN_OT)

    sessions = kb.get("verified_session_ids") or kb.get("verified_sessions") or kb.get("sessions") or []
    if sessions and phase_l in {"post", "act", "reason", "exploit", ""}:
        _add(DOMAIN_POST)

    try:
        from interfaces.command_system.builtin.agent.specialist_army import specialist_army_enabled

        if specialist_army_enabled(kb=kb) and httpish and DOMAIN_WEB in active:
            # Army mode: keep web corps but allow orchestrator to fan out across corps.
            pass
    except Exception:
        pass

    if not active:
        _add(DOMAIN_WEB if httpish else DOMAIN_NETWORK)
    return active[:8]
