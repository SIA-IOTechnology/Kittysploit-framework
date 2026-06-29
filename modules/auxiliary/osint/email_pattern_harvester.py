from kittysploit import *
import json
import os
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Email Pattern Harvester",
        "author": ["KittySploit Team"],
        "description": (
            "Harvest organizational email addresses and patterns from passive sources: "
            "DMARC/SPF TXT records, RDAP contacts, and certificate transparency naming hints."
        ),
        "tags": ["osint", "passive", "email", "harvest", "identity"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    scan_cert_names = OptBool(True, "Extract email-like hints from crt.sh certificate names", required=False)
    max_cert_names = OptString("300", "Max certificate names to process", required=False)
    timeout = OptString("12", "HTTP/DNS timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    EMAIL_RE = re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    )
    COMMON_LOCAL_PARTS = (
        "info", "contact", "admin", "support", "security", "abuse",
        "sales", "hr", "helpdesk", "noreply", "postmaster", "webmaster",
        "it", "devops", "billing", "legal", "privacy", "ceo", "cto",
    )

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

    def _dns_txt(self, name, timeout_seconds):
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            return [r.to_text().strip('"') for r in resolver.resolve(name, "TXT")]
        except Exception:
            return []

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
            self.ssl = scheme == "https"
            return self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _rdap_emails(self, domain, timeout_seconds):
        emails = set()
        try:
            url = f"https://rdap.org/domain/{domain}"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp or resp.status_code != 200:
                return []
            data = resp.json()
            raw = json.dumps(data)
            for match in self.EMAIL_RE.findall(raw):
                if domain in match.lower():
                    emails.add(match.lower())
        except Exception:
            pass
        return sorted(emails)

    def _dmarc_spf_emails(self, domain, timeout_seconds):
        emails = set()
        sources = [
            f"_dmarc.{domain}",
            domain,
        ]
        for name in sources:
            for txt in self._dns_txt(name, timeout_seconds):
                for match in self.EMAIL_RE.findall(txt):
                    emails.add(match.lower())
                if "rua=mailto:" in txt.lower():
                    for part in re.findall(r"rua=mailto:([^;,\s]+)", txt, re.I):
                        if "@" in part:
                            emails.add(part.lower())
                if "ruf=mailto:" in txt.lower():
                    for part in re.findall(r"ruf=mailto:([^;,\s]+)", txt, re.I):
                        if "@" in part:
                            emails.add(part.lower())
        return sorted(emails)

    def _crtsh_hints(self, domain, timeout_seconds, limit):
        hints = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200:
            return []
        try:
            rows = resp.json()
        except Exception:
            return []
        count = 0
        for row in rows:
            name_value = str(row.get("name_value", ""))
            for match in self.EMAIL_RE.findall(name_value):
                if domain in match.lower():
                    hints.add(match.lower())
            for item in name_value.split("\n"):
                item = item.strip().lower()
                if "@" in item and domain in item:
                    hints.add(item)
            count += 1
            if count >= limit:
                break
        return sorted(hints)

    def _infer_patterns(self, emails, domain):
        patterns = set()
        local_parts = set()
        for email in emails:
            if "@" not in email:
                continue
            local = email.split("@", 1)[0]
            local_parts.add(local)
            if "." in local:
                patterns.add("{first}.{last}@" + domain)
            elif local.isalpha():
                patterns.add(f"{local}@" + domain)

        for common in self.COMMON_LOCAL_PARTS:
            patterns.add(f"{common}@{domain}")

        return {
            "observed_local_parts": sorted(local_parts)[:40],
            "likely_patterns": sorted(patterns)[:30],
        }

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid domain target"}

        timeout_seconds = self._to_int(self.timeout, 12)
        max_cert = self._to_int(self.max_cert_names, 300)

        print_info(f"Harvesting email intelligence for {domain}")
        sources = {}

        print_status("Parsing DMARC/SPF TXT records...")
        sources["dmarc_spf"] = self._dmarc_spf_emails(domain, timeout_seconds)

        print_status("Querying RDAP contacts...")
        sources["rdap"] = self._rdap_emails(domain, timeout_seconds)

        if self.scan_cert_names:
            print_status("Scanning certificate transparency names...")
            sources["certificate_transparency"] = self._crtsh_hints(domain, timeout_seconds, max_cert)
        else:
            sources["certificate_transparency"] = []

        all_emails = set()
        for key, values in sources.items():
            for email in values:
                if email.endswith(f"@{domain}") or f"@{domain}" in email:
                    all_emails.add(email.lower())

        patterns = self._infer_patterns(sorted(all_emails), domain)
        count = len(all_emails)
        risk_level = "HIGH" if count >= 15 else ("MEDIUM" if count >= 5 else "LOW")

        data = {
            "target": domain,
            "email_count": count,
            "risk_level": risk_level,
            "emails": sorted(all_emails)[:100],
            "sources": {k: v[:30] for k, v in sources.items()},
            "patterns": patterns,
        }

        print_success(f"Email harvest: {count} address(es) / pattern(s) (risk={risk_level})")
        for email in sorted(all_emails)[:12]:
            print_info(f"  {email}")
        if patterns.get("likely_patterns"):
            print_info(f"Likely patterns: {', '.join(patterns['likely_patterns'][:5])}")

        if self.output_file:
            try:
                parent = os.path.dirname(str(self.output_file))
                if parent:
                    os.makedirs(parent, exist_ok=True)
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
        for i, email in enumerate(data.get("emails", [])[:20]):
            nid = f"email_{i}"
            nodes.append({"id": nid, "label": email, "group": "email", "icon": "📧"})
            edges.append({"from": target, "to": nid, "label": "email"})
        return nodes, edges
