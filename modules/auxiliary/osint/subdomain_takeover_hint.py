from kittysploit import *
import json
import dns.resolver
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Subdomain Takeover Hint",
        "author": ["KittySploit Team"],
        "description": "Detect possible subdomain takeover indicators from DNS CNAME and HTTP fingerprints.",
        "tags": ["osint", "passive", "subdomain", "takeover"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    max_subdomains = OptString("40", "Maximum subdomains to inspect", required=False)
    timeout = OptString("8", "HTTP/DNS timeout in seconds", required=False)
    min_confidence = OptString("70", "Minimum confidence to keep a finding (0-100)", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

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
            return self.http_request(method="GET", path=path, allow_redirects=True, timeout=timeout_seconds)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    FINGERPRINTS = [
        ("github.io", ["there isn't a github pages site here", "repository not found"]),
        ("herokudns.com", ["no such app", "there is nothing here"]),
        ("azurewebsites.net", ["404 web site not found", "this web app is stopped"]),
        ("cloudfront.net", ["the request could not be satisfied"]),
        ("fastly.net", ["fastly error: unknown domain"]),
        ("pantheonsite.io", ["the gods are wise", "404 error unknown site"]),
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _dns_txt(self, host, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            return [r.to_text().strip() for r in resolver.resolve(host, "TXT")]
        except Exception:
            return []

    def _dns_cname(self, host, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            answers = resolver.resolve(host, "CNAME")
            return [r.to_text().rstrip(".").lower() for r in answers]
        except Exception:
            return []

    def _dns_resolves(self, host, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            resolver.resolve(host, "A")
            return True
        except Exception:
            pass
        try:
            resolver.resolve(host, "CNAME")
            return True
        except Exception:
            return False

    def _crtsh_subdomains(self, domain, timeout_seconds):
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                return []
            if resp.status_code != 200:
                return []
            rows = resp.json()
            subs = set()
            for row in rows:
                value = row.get("name_value", "")
                for item in value.split("\n"):
                    s = item.strip().lower()
                    if s and "*" not in s and s.endswith(domain):
                        subs.add(s)
            return sorted(subs)
        except Exception:
            return []

    def _http_probe(self, host, timeout_seconds):
        url = f"https://{host}"
        try:
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                return None, "", url
            body = (resp.text or "")[:5000].lower()
            return resp.status_code, body, resp.url
        except Exception:
            return None, "", url

    def _match_takeover_hint(self, cname, body):
        if not cname:
            return None
        for provider, patterns in self.FINGERPRINTS:
            if provider in cname:
                for p in patterns:
                    if p in body:
                        return provider, p, True
                return provider, None, False
        return None

    def run(self):
        domain = str(self.target).strip().lower()
        if not domain:
            print_error("target is required")
            return {"error": "target is required"}

        timeout_seconds = self._to_int(self.timeout, 8)
        max_subdomains = self._to_int(self.max_subdomains, 40)
        min_confidence = min(100, self._to_int(self.min_confidence, 70))
        print_info(f"Checking takeover hints for {domain}")

        subdomains = self._crtsh_subdomains(domain, timeout_seconds)[:max_subdomains]
        if not subdomains:
            print_warning("No subdomain found from crt.sh (or source unavailable)")

        findings = []
        for sub in subdomains:
            cnames = self._dns_cname(sub, timeout_seconds)
            if not cnames:
                continue
            cname = cnames[0]

            status_code, body, final_url = self._http_probe(sub, timeout_seconds)
            hint = self._match_takeover_hint(cname, body)
            if not hint:
                continue

            provider, pattern, fp_hit = hint
            cname_target_resolves = self._dns_resolves(cname, timeout_seconds)

            confidence = 30
            if fp_hit:
                confidence = 75
            if status_code in (404, 410):
                confidence += 10
            if not cname_target_resolves:
                confidence += 15
            confidence = min(95, confidence)

            # Reduce false positives: keep only strong indicators.
            if confidence < min_confidence:
                continue

            findings.append({
                "subdomain": sub,
                "cname": cname,
                "provider_hint": provider,
                "fingerprint_match": pattern,
                "cname_target_resolves": cname_target_resolves,
                "http_status": status_code,
                "url": final_url,
                "confidence": confidence,
            })

        findings = sorted(findings, key=lambda x: x.get("confidence", 0), reverse=True)
        risk_level = "LOW"
        if any(f["confidence"] >= 85 for f in findings):
            risk_level = "HIGH"
        elif findings:
            risk_level = "MEDIUM"

        data = {
            "target": domain,
            "checked_subdomains": len(subdomains),
            "count": len(findings),
            "risk_level": risk_level,
            "findings": findings,
        }

        if findings:
            print_warning(f"Potential takeover hints found: {len(findings)} (risk={risk_level})")
            for f in findings[:15]:
                print_info(
                    f"  {f['subdomain']} -> {f['cname']} | {f['provider_hint']} "
                    f"| status={f['http_status']} | confidence={f['confidence']}"
                )
        else:
            print_success("No takeover hint detected from analyzed subdomains")

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
        for i, f in enumerate(data.get("findings", [])[:20]):
            nid = f"takeover_{i}_{target}"
            provider = f.get("provider_hint", "provider")
            nodes.append({
                "id": nid,
                "label": f"{f.get('subdomain')} -> {provider} ({f.get('confidence')})",
                "group": "hostname",
                "icon": "🧷",
            })
            edges.append({"from": target, "to": nid, "label": "takeover"})
        return nodes, edges
