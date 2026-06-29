from kittysploit import *
import ipaddress
import json
import re
from urllib.parse import urlparse

import dns.resolver

from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "CDN Origin IP Finder",
        "author": ["KittySploit Team"],
        "description": (
            "Find probable origin server IPs hidden behind CDNs (Cloudflare, Fastly, Akamai) "
            "by correlating DNS on direct/staging subdomains, MX records, and CT enumeration."
        ),
        "tags": ["osint", "passive", "cdn", "origin-ip", "infrastructure"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    scan_cert_subdomains = OptBool(True, "Enumerate crt.sh subdomains and resolve A records", required=False)
    max_cert_names = OptString("200", "Max certificate names to resolve", required=False)
    timeout = OptString("10", "DNS/HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    ORIGIN_HINT_PREFIXES = (
        "direct", "origin", "origin-www", "www-origin", "real", "server",
        "staging", "stage", "stg", "dev", "test", "uat", "preprod", "beta",
        "mail", "smtp", "mx", "mx1", "ftp", "cpanel", "webmail", "owa",
        "vpn", "remote", "api", "old", "legacy", "backend", "internal",
    )

    CDN_NETWORKS = [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "23.235.32.0/20", "2400:cb00::/32", "2606:4700::/32",
        "2803:f800::/32", "2a06:98c0::/29", "2c0f:f248::/32",
        "151.101.0.0/16", "199.232.0.0/16",
        "23.0.0.0/12",
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_domain(self, value):
        domain = str(value).strip().lower()
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/", 1)[0].strip(".")
        if "@" in domain or not domain or "." not in domain:
            return None
        return domain

    def _cdn_networks(self):
        nets = []
        for cidr in self.CDN_NETWORKS:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except Exception:
                pass
        return nets

    def _is_cdn_ip(self, ip_str, cdn_nets):
        try:
            ip = ipaddress.ip_address(ip_str)
        except Exception:
            return False
        return any(ip in net for net in cdn_nets)

    def _dns_a(self, host, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            return [r.address for r in resolver.resolve(host, "A")]
        except Exception:
            return []

    def _dns_mx_hosts(self, domain, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        hosts = []
        try:
            for r in resolver.resolve(domain, "MX"):
                mx_host = str(r.exchange).rstrip(".")
                if mx_host:
                    hosts.append(mx_host)
        except Exception:
            pass
        return hosts

    def _http_get_url(self, url, timeout_seconds):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = scheme == "https"
            return self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _crtsh_subdomains(self, domain, timeout_seconds, limit):
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200:
            return []
        try:
            rows = resp.json()
        except Exception:
            return []
        subs = set()
        for row in rows:
            for item in str(row.get("name_value", "")).split("\n"):
                host = item.strip().lower()
                if host and "*" not in host and host.endswith(domain):
                    subs.add(host)
            if len(subs) >= limit:
                break
        return sorted(subs)[:limit]

    def _confidence(self, hostname, source, is_cdn, apex_is_cdn):
        score = 40
        if not is_cdn and apex_is_cdn:
            score += 35
        if source in ("origin_hint_subdomain", "mx_host"):
            score += 15
        if any(p in hostname for p in ("origin", "direct", "staging", "dev", "internal")):
            score += 10
        return min(95, score)

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid domain target"}

        timeout_seconds = self._to_int(self.timeout, 10)
        max_cert = self._to_int(self.max_cert_names, 200)
        cdn_nets = self._cdn_networks()

        print_info(f"Hunting origin IPs for {domain} (behind CDN detection)")
        apex_ips = self._dns_a(domain, timeout_seconds)
        apex_cdn = all(self._is_cdn_ip(ip, cdn_nets) for ip in apex_ips) if apex_ips else False

        hosts_to_check = {domain}
        for prefix in self.ORIGIN_HINT_PREFIXES:
            hosts_to_check.add(f"{prefix}.{domain}")

        if self.scan_cert_subdomains:
            print_status("Collecting subdomains from crt.sh...")
            for sub in self._crtsh_subdomains(domain, timeout_seconds, max_cert):
                hosts_to_check.add(sub)

        for mx in self._dns_mx_hosts(domain, timeout_seconds):
            hosts_to_check.add(mx)

        findings = []
        seen_ip_host = set()

        for host in sorted(hosts_to_check):
            ips = self._dns_a(host, timeout_seconds)
            for ip in ips:
                key = (ip, host)
                if key in seen_ip_host:
                    continue
                seen_ip_host.add(key)

                is_cdn = self._is_cdn_ip(ip, cdn_nets)
                if is_cdn and apex_cdn:
                    continue

                source = "subdomain"
                if host == domain:
                    source = "apex"
                elif host.endswith(f".{domain}") and host.split(".", 1)[0] in self.ORIGIN_HINT_PREFIXES:
                    source = "origin_hint_subdomain"
                elif not host.endswith(domain):
                    source = "mx_host"

                confidence = self._confidence(host, source, is_cdn, apex_cdn)
                if confidence < 50:
                    continue

                findings.append({
                    "ip": ip,
                    "hostname": host,
                    "source": source,
                    "cdn_ip": is_cdn,
                    "confidence": confidence,
                })

        findings.sort(key=lambda x: (-x.get("confidence", 0), x.get("ip", "")))
        unique_ips = sorted({f["ip"] for f in findings})

        risk_level = "HIGH" if any(f["confidence"] >= 80 for f in findings) else (
            "MEDIUM" if findings else "LOW"
        )

        data = {
            "target": domain,
            "apex_ips": apex_ips,
            "apex_behind_cdn": apex_cdn,
            "origin_ip_candidates": unique_ips,
            "candidate_count": len(findings),
            "risk_level": risk_level,
            "findings": findings[:50],
        }

        print_success(
            f"Origin hunt: apex_cdn={apex_cdn}, candidates={len(unique_ips)} IP(s) (risk={risk_level})"
        )
        for f in findings[:10]:
            print_info(
                f"  [{f.get('confidence')}] {f.get('ip')} via {f.get('hostname')} "
                f"({f.get('source')})"
            )

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        target = data.get("target", self.target)
        nodes = []
        edges = []
        for i, f in enumerate(data.get("findings", [])[:15]):
            nid = f"origin_{i}_{f.get('ip')}"
            nodes.append({
                "id": nid,
                "label": f"{f.get('ip')} ({f.get('hostname')})",
                "group": "ip",
                "icon": "🎯",
            })
            edges.append({"from": target, "to": nid, "label": "origin?"})
        return nodes, edges
