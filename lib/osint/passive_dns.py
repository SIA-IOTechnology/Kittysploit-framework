#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Passive DNS / subdomain aggregation helpers."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

import dns.resolver

DEFAULT_PERMUTATIONS = (
    "www", "mail", "remote", "vpn", "api", "dev", "staging", "stage", "test",
    "uat", "beta", "admin", "portal", "intranet", "extranet", "cdn", "static",
    "assets", "app", "apps", "m", "mobile", "shop", "store", "git", "gitlab",
    "jenkins", "ci", "cd", "grafana", "kibana", "elastic", "auth", "login",
    "sso", "id", "mx", "smtp", "ftp", "ns1", "ns2", "old", "legacy", "backup",
)


def normalize_domain(value: str) -> Optional[str]:
    domain = str(value or "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/", 1)[0].strip(".")
    if not domain or "." not in domain or "@" in domain:
        return None
    return domain


def permute_subdomains(domain: str, prefixes: Iterable[str]) -> List[str]:
    hosts: Set[str] = set()
    for prefix in prefixes:
        p = str(prefix).strip().lower().strip(".")
        if not p or p == "*":
            continue
        hosts.add(f"{p}.{domain}")
    return sorted(hosts)


def fetch_crtsh_subdomains(domain: str, http_get, timeout: float = 10.0) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = http_get(url, timeout)
    if not resp or getattr(resp, "status_code", 0) != 200:
        return []
    try:
        rows = resp.json()
    except Exception:
        return []
    hosts: Set[str] = set()
    for row in rows:
        for item in str(row.get("name_value", "")).split("\n"):
            host = item.strip().lower()
            if host and "*" not in host and host.endswith(domain):
                hosts.add(host)
    return sorted(hosts)


def resolve_hosts(hosts: Iterable[str], timeout: float = 5.0) -> Dict[str, List[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records: Dict[str, List[str]] = {}
    for host in hosts:
        try:
            answers = resolver.resolve(host, "A")
            records[host] = [r.to_text() for r in answers]
        except Exception:
            records[host] = []
    return records


def aggregate_passive_dns(
    domain: str,
    *,
    http_get,
    include_ct: bool = True,
    include_permutations: bool = True,
    permutation_prefixes: Optional[Iterable[str]] = None,
    resolve_a: bool = False,
    max_resolve: int = 40,
    timeout: float = 10.0,
) -> Dict[str, object]:
    domain = normalize_domain(domain) or ""
    if not domain:
        return {"error": "invalid_domain", "target": domain}

    sources: Dict[str, List[str]] = {}
    all_hosts: Set[str] = set()

    if include_ct:
        ct_hosts = fetch_crtsh_subdomains(domain, http_get, timeout=timeout)
        sources["certificate_transparency"] = ct_hosts
        all_hosts.update(ct_hosts)

    if include_permutations:
        prefixes = list(permutation_prefixes or DEFAULT_PERMUTATIONS)
        perm_hosts = permute_subdomains(domain, prefixes)
        sources["permutations"] = perm_hosts
        all_hosts.update(perm_hosts)

    all_hosts.add(domain)
    hosts_sorted = sorted(all_hosts)
    data: Dict[str, object] = {
        "target": domain,
        "count": len(hosts_sorted),
        "subdomains": hosts_sorted,
        "sources": sources,
        "resolved": {},
        "resolved_count": 0,
    }

    if resolve_a:
        to_resolve = hosts_sorted[: max(1, max_resolve)]
        resolved = resolve_hosts(to_resolve, timeout=min(timeout, 5.0))
        live = {host: ips for host, ips in resolved.items() if ips}
        data["resolved"] = live
        data["resolved_count"] = len(live)
    return data
