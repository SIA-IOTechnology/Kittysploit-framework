from kittysploit import *
import json
import dns.resolver
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Domain Surface Mapper",
        "author": ["KittySploit Team"],
        "description": "Map domain attack surface using DNS, WHOIS, CT subdomains, and HTTP security headers.",
        "tags": ["osint", "passive", "domain", "surface"],
    }

    target = OptString("", "The target domain (e.g. example.com)", required=True)
    resolve_dns = OptBool(True, "Resolve DNS records (A, MX, NS, TXT)", False)
    check_subdomains = OptBool(True, "Enumerate subdomains via crt.sh", False)
    check_headers = OptBool(True, "Fetch HTTP headers for target and selected subdomains", False)
    max_subdomains = OptString("20", "Maximum subdomains to check for HTTP headers", False)
    timeout = OptString("10", "HTTP/DNS timeout in seconds", False)
    output_file = OptString("", "Optional JSON output file", False)

    def _http_get_url(self, url, timeout_seconds):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = (scheme == "https")
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _normalize_domain(self, value):
        domain = str(value).strip().lower()
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/", 1)[0].strip(".")
        if "@" in domain:
            return None
        if not domain or "." not in domain:
            return None
        return domain

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _dns_lookup(self, domain, rtype, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            answers = resolver.resolve(domain, rtype)
            return [r.to_text() for r in answers]
        except Exception:
            return []

    def _whois_lookup(self, domain):
        # Keep lightweight and dependency-safe: use rdap.org public endpoint.
        # This is best-effort and may be limited by TLD/availability.
        try:
            url = f"https://rdap.org/domain/{domain}"
            resp = self._http_get_url(url, 10)
            if not resp:
                return {}
            if resp.status_code != 200:
                return {}
            data = resp.json()
            registrar = ""
            entities = data.get("entities", [])
            for ent in entities:
                vcard = (ent.get("vcardArray") or [None, []])[1]
                for row in vcard:
                    if len(row) >= 4 and row[0] == "fn":
                        registrar = row[3]
                        break
                if registrar:
                    break

            return {
                "registrar": registrar,
                "status": data.get("status", []),
                "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")],
                "events": data.get("events", []),
            }
        except Exception:
            return {}

    def _crtsh_subdomains(self, domain, timeout_seconds):
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                return []
            if resp.status_code != 200:
                return []
            rows = resp.json()
            subdomains = set()
            for row in rows:
                name_value = row.get("name_value", "")
                for item in name_value.split("\n"):
                    host = item.strip().lower()
                    if host and "*" not in host and host.endswith(domain):
                        subdomains.add(host)
            return sorted(subdomains)
        except Exception:
            return []

    def _fetch_headers(self, host, timeout_seconds):
        target_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
        headers = {}
        status_code = None
        final_url = target_url
        transport = "https"
        resp = self._http_get_url(target_url, timeout_seconds)
        if not resp:
            fallback_url = host if host.startswith("http://") else f"http://{host.replace('https://', '').replace('http://', '')}"
            resp = self._http_get_url(fallback_url, timeout_seconds)
            if resp:
                target_url = fallback_url
                transport = "http_fallback"
        if not resp:
            return {
                "url": target_url,
                "status_code": None,
                "final_url": final_url,
                "headers": {},
                "score": 0,
                "issues": ["request_failed"],
                "transport": "failed",
            }
        status_code = resp.status_code
        final_url = resp.url
        headers = {k: v for k, v in resp.headers.items()}

        required_security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
        ]
        missing = [h for h in required_security_headers if h not in headers]
        issues = []
        if missing:
            issues.append(f"missing_security_headers:{','.join(missing)}")
        if headers.get("Server"):
            issues.append("server_header_exposed")
        if status_code and status_code >= 500:
            issues.append("server_error_status")
        score = 100
        score -= min(60, len(missing) * 10)
        if "server_header_exposed" in issues:
            score -= 10
        if "server_error_status" in issues:
            score -= 15
        score = max(0, score)

        return {
            "url": target_url,
            "status_code": status_code,
            "final_url": final_url,
            "headers": headers,
            "score": score,
            "issues": issues,
            "transport": transport,
        }

    def _surface_risk(self, data):
        risk = 0
        signals = []

        sub_count = len(data.get("subdomains", []))
        if sub_count >= 100:
            risk += 3
            signals.append("very_large_subdomain_surface")
        elif sub_count >= 25:
            risk += 2
            signals.append("large_subdomain_surface")
        elif sub_count >= 10:
            risk += 1
            signals.append("moderate_subdomain_surface")

        headers = data.get("http_checks", [])
        weak_headers = [h for h in headers if h.get("score", 100) < 60]
        if weak_headers:
            risk += 2
            signals.append("weak_http_security_headers")

        dns_records = data.get("dns", {})
        if len(dns_records.get("TXT", [])) > 15:
            risk += 1
            signals.append("many_txt_records")

        if risk >= 5:
            level = "HIGH"
        elif risk >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "risk_score": risk,
            "risk_level": level,
            "signals": signals,
        }

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain (email values are not accepted)")
            return {"error": "invalid domain target"}

        timeout_seconds = self._to_int(self.timeout, 10)
        max_subdomains = self._to_int(self.max_subdomains, 20)

        print_info(f"Mapping surface for: {domain}")
        result = {
            "target": domain,
            "dns": {},
            "whois": {},
            "subdomains": [],
            "http_checks": [],
        }

        if self.resolve_dns:
            print_status("Resolving DNS records...")
            for rtype in ["A", "MX", "NS", "TXT"]:
                result["dns"][rtype] = self._dns_lookup(domain, rtype, timeout_seconds)
            print_success(
                f"DNS done: A={len(result['dns'].get('A', []))}, "
                f"MX={len(result['dns'].get('MX', []))}, "
                f"NS={len(result['dns'].get('NS', []))}, "
                f"TXT={len(result['dns'].get('TXT', []))}"
            )

        print_status("Collecting WHOIS/RDAP info...")
        result["whois"] = self._whois_lookup(domain)

        if self.check_subdomains:
            print_status("Enumerating subdomains via crt.sh...")
            result["subdomains"] = self._crtsh_subdomains(domain, timeout_seconds)
            print_success(f"Subdomains found: {len(result['subdomains'])}")

        if self.check_headers:
            print_status("Checking HTTP security headers...")
            targets = [domain]
            targets.extend(result["subdomains"][:max_subdomains])
            seen = set()
            http_checks = []
            for host in targets:
                if host in seen:
                    continue
                seen.add(host)
                http_checks.append(self._fetch_headers(host, timeout_seconds))
            result["http_checks"] = http_checks
            weak = [x for x in http_checks if x.get("score", 100) < 60]
            print_info(f"HTTP checks: {len(http_checks)} host(s), weak={len(weak)}")

        risk = self._surface_risk(result)
        result.update(risk)

        print_info("=" * 80)
        print_success(
            f"Surface summary: risk={result['risk_level']} score={result['risk_score']} "
            f"subdomains={len(result.get('subdomains', []))}"
        )
        if result["signals"]:
            print_info(f"Signals: {', '.join(result['signals'])}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as f:
                    json.dump(result, f, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return result

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []

        target = data.get("target", self.target)
        nodes = []
        edges = []

        # Subdomains
        for sub in data.get("subdomains", [])[:20]:
            nid = f"sub_{sub}"
            nodes.append({"id": nid, "label": sub, "group": "subdomain", "icon": "🌐"})
            edges.append({"from": target, "to": nid, "label": "subdomain"})

        # A records
        for ip in data.get("dns", {}).get("A", [])[:15]:
            nid = f"ip_{ip}"
            nodes.append({"id": nid, "label": ip, "group": "ip", "icon": "🖥️"})
            edges.append({"from": target, "to": nid, "label": "A"})

        # Weak HTTP nodes
        for idx, hc in enumerate(data.get("http_checks", [])[:15]):
            if hc.get("score", 100) >= 60:
                continue
            url = hc.get("final_url") or hc.get("url")
            nid = f"weak_http_{idx}"
            nodes.append({
                "id": nid,
                "label": f"Weak headers: {url}",
                "group": "hostname",
                "icon": "🛡️",
            })
            edges.append({"from": target, "to": nid, "label": "http"})

        return nodes, edges
