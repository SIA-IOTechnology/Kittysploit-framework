#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS probes inspired by NSE dns-zone-transfer / recursion / srv-enum / nsid."""

from __future__ import annotations

from typing import Dict, List


def _dns():
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.flags

    return dns


def probe_dns_zone_transfer(
    host: str,
    domain: str,
    port: int = 53,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """Attempt AXFR against *host* for *domain* (NSE dns-zone-transfer)."""
    result: Dict[str, object] = {
        "vulnerable": False,
        "records": [],
        "error": "",
    }
    domain = (domain or "").strip().rstrip(".")
    if not domain:
        result["error"] = "missing_domain"
        return result
    try:
        import dns.query
        import dns.zone
        import dns.exception

        zone = dns.zone.from_xfr(
            dns.query.xfr(host, domain, timeout=timeout, port=int(port), lifetime=timeout)
        )
        names: List[str] = []
        for name, _node in zone.nodes.items():
            rel = name.to_text()
            fqdn = domain if rel in (".", "@") else f"{rel}.{domain}"
            names.append(fqdn)
            if len(names) >= 50:
                break
        result["vulnerable"] = True
        result["records"] = names
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


def probe_dns_recursion(
    host: str,
    port: int = 53,
    timeout: float = 3.0,
    qname: str = "example.com",
) -> Dict[str, object]:
    """Check if resolver answers recursive queries for third-party names."""
    result: Dict[str, object] = {
        "recursion_available": False,
        "answers": [],
        "error": "",
    }
    try:
        dns = _dns()
        req = dns.message.make_query(qname, dns.rdatatype.A)
        req.flags |= dns.flags.RD
        resp = dns.query.udp(req, host, timeout=timeout, port=int(port))
        ra = bool(resp.flags & dns.flags.RA)
        result["recursion_available"] = ra
        answers: List[str] = []
        for rrset in resp.answer:
            for item in rrset:
                answers.append(item.to_text())
        result["answers"] = answers[:8]
        if not ra and not answers:
            result["error"] = "no_recursion"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


def probe_dns_nsid(
    host: str,
    port: int = 53,
    timeout: float = 3.0,
) -> Dict[str, object]:
    """Query CHAOS TXT id.server / version.bind and EDNS NSID (NSE dns-nsid)."""
    result: Dict[str, object] = {
        "detected": False,
        "id_server": "",
        "version_bind": "",
        "nsid": "",
        "error": "",
    }
    try:
        import dns.edns
        import dns.message
        import dns.query
        import dns.rdataclass
        import dns.rdatatype

        for qname, key in (("id.server", "id_server"), ("version.bind", "version_bind")):
            req = dns.message.make_query(qname, dns.rdatatype.TXT, rdclass=dns.rdataclass.CH)
            try:
                resp = dns.query.udp(req, host, timeout=timeout, port=int(port))
            except Exception:
                continue
            for rrset in resp.answer:
                for item in rrset:
                    text = item.to_text().strip('"')
                    if text:
                        result[key] = text[:200]
                        result["detected"] = True

        req = dns.message.make_query(".", dns.rdatatype.NS)
        req.use_edns(edns=True, options=[dns.edns.GenericOption(dns.edns.OptionType.NSID, b"")])
        try:
            resp = dns.query.udp(req, host, timeout=timeout, port=int(port))
            for opt in resp.options:
                if getattr(opt, "otype", None) == dns.edns.OptionType.NSID:
                    raw = getattr(opt, "data", b"") or b""
                    try:
                        result["nsid"] = raw.decode("utf-8", errors="replace")[:200]
                    except Exception:
                        result["nsid"] = raw.hex()
                    result["detected"] = True
        except Exception:
            pass
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


# Common SRV names useful for AD / mail / VoIP recon (NSE dns-srv-enum)
DEFAULT_SRV_SERVICES = (
    "_ldap._tcp",
    "_ldap._tcp.dc._msdcs",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_kpasswd._tcp",
    "_gc._tcp",
    "_sip._tcp",
    "_sip._udp",
    "_xmpp-server._tcp",
    "_xmpp-client._tcp",
    "_autodiscover._tcp",
)


def probe_dns_srv_enum(
    host: str,
    domain: str,
    port: int = 53,
    timeout: float = 3.0,
    services: List[str] | None = None,
) -> Dict[str, object]:
    """Enumerate common SRV records for a domain via a specific nameserver."""
    result: Dict[str, object] = {
        "found": False,
        "records": [],
        "error": "",
    }
    domain = (domain or "").strip().rstrip(".")
    if not domain:
        result["error"] = "missing_domain"
        return result
    try:
        import dns.message
        import dns.query
        import dns.rdatatype

        svc_list = services or list(DEFAULT_SRV_SERVICES)
        records: List[Dict[str, object]] = []
        for svc in svc_list:
            qname = f"{svc}.{domain}"
            req = dns.message.make_query(qname, dns.rdatatype.SRV)
            try:
                resp = dns.query.udp(req, host, timeout=timeout, port=int(port))
            except Exception:
                continue
            for rrset in resp.answer:
                for item in rrset:
                    entry = {
                        "service": qname,
                        "priority": int(getattr(item, "priority", 0)),
                        "weight": int(getattr(item, "weight", 0)),
                        "port": int(getattr(item, "port", 0)),
                        "target": str(getattr(item, "target", "")).rstrip("."),
                    }
                    records.append(entry)
        result["records"] = records
        result["found"] = bool(records)
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


DEFAULT_CACHE_SNOOP_NAMES = (
    "www.google.com",
    "www.facebook.com",
    "www.youtube.com",
    "www.amazon.com",
    "www.microsoft.com",
    "www.apple.com",
    "www.cloudflare.com",
    "www.wikipedia.org",
)


def probe_dns_cache_snoop(
    host: str,
    port: int = 53,
    timeout: float = 2.0,
    names: List[str] | None = None,
) -> Dict[str, object]:
    """
    Non-recursive A queries — answers imply names are cached (NSE dns-cache-snoop).
    """
    result: Dict[str, object] = {
        "snoopable": False,
        "cached": [],
        "checked": 0,
        "error": "",
    }
    try:
        import dns.flags
        import dns.message
        import dns.query
        import dns.rdatatype

        cached: List[str] = []
        for qname in names or list(DEFAULT_CACHE_SNOOP_NAMES):
            result["checked"] = int(result["checked"]) + 1
            req = dns.message.make_query(qname, dns.rdatatype.A)
            # Clear RD — non-recursive
            req.flags &= ~dns.flags.RD
            try:
                resp = dns.query.udp(req, host, timeout=timeout, port=int(port))
            except Exception:
                continue
            if resp.answer:
                cached.append(qname)
        result["cached"] = cached
        result["snoopable"] = bool(cached)
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


DEFAULT_DNS_BRUTE_WORDS = (
    "www",
    "mail",
    "webmail",
    "smtp",
    "pop",
    "imap",
    "ftp",
    "ns1",
    "ns2",
    "dns",
    "vpn",
    "remote",
    "portal",
    "admin",
    "api",
    "dev",
    "staging",
    "test",
    "cdn",
    "autodiscover",
    "lyncdiscover",
    "owa",
    "exchange",
    "ad",
    "dc",
    "ldap",
    "git",
    "ci",
    "jenkins",
    "grafana",
)


def probe_dns_brute(
    host: str,
    domain: str,
    port: int = 53,
    timeout: float = 2.0,
    wordlist: List[str] | None = None,
) -> Dict[str, object]:
    """Brute common subdomains against a nameserver (NSE dns-brute)."""
    result: Dict[str, object] = {
        "found": False,
        "hosts": [],
        "error": "",
    }
    domain = (domain or "").strip().rstrip(".")
    if not domain:
        result["error"] = "missing_domain"
        return result
    try:
        import dns.message
        import dns.query
        import dns.rdatatype

        hosts: List[Dict[str, object]] = []
        for label in wordlist or list(DEFAULT_DNS_BRUTE_WORDS):
            qname = f"{label}.{domain}"
            req = dns.message.make_query(qname, dns.rdatatype.A)
            try:
                resp = dns.query.udp(req, host, timeout=timeout, port=int(port))
            except Exception:
                continue
            addrs = []
            for rrset in resp.answer:
                for item in rrset:
                    addrs.append(item.to_text())
            if addrs:
                hosts.append({"name": qname, "addresses": addrs[:8]})
        result["hosts"] = hosts
        result["found"] = bool(hosts)
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


def probe_dns_update(
    host: str,
    domain: str,
    name: str = "kittysploit-probe",
    ip: str = "127.0.0.1",
    port: int = 53,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """
    Attempt unauthenticated dynamic DNS UPDATE (NSE dns-update).
    Adds then deletes a probe A record — reports if the server accepted the update.
    """
    result: Dict[str, object] = {
        "vulnerable": False,
        "rcode": "",
        "error": "",
    }
    domain = (domain or "").strip().rstrip(".")
    name = (name or "kittysploit-probe").strip().rstrip(".")
    if not domain:
        result["error"] = "missing_domain"
        return result
    fqdn = f"{name}.{domain}" if not name.endswith(domain) else name
    try:
        import dns.query
        import dns.rcode
        import dns.update

        update = dns.update.Update(domain)
        update.add(fqdn, 60, "A", ip)
        resp = dns.query.tcp(update, host, timeout=timeout, port=int(port))
        rcode = dns.rcode.to_text(resp.rcode())
        result["rcode"] = rcode
        if resp.rcode() == dns.rcode.NOERROR:
            result["vulnerable"] = True
            # Cleanup
            try:
                cleanup = dns.update.Update(domain)
                cleanup.delete(fqdn, "A")
                dns.query.tcp(cleanup, host, timeout=timeout, port=int(port))
            except Exception:
                pass
        return result
    except Exception as exc:
        # Try UDP as fallback
        try:
            import dns.query
            import dns.rcode
            import dns.update

            update = dns.update.Update(domain)
            update.add(fqdn, 60, "A", ip)
            resp = dns.query.udp(update, host, timeout=timeout, port=int(port))
            rcode = dns.rcode.to_text(resp.rcode())
            result["rcode"] = rcode
            if resp.rcode() == dns.rcode.NOERROR:
                result["vulnerable"] = True
            return result
        except Exception as exc2:
            result["error"] = str(exc2)[:200]
            return result
