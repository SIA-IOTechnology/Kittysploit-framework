from kittysploit import *
import json
import re
from urllib.parse import quote, urlparse

import dns.resolver

from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "SaaS Tenant Discovery",
        "author": ["KittySploit Team"],
        "description": (
            "Passive discovery of public SaaS / IdP signals for an organization domain: "
            "Microsoft 365 (realm, autodiscover), Google Workspace, Okta, Auth0, Atlassian, "
            "Slack, Notion, and common mail/SaaS SPF-MX hints via DNS and optional certificate transparency."
        ),
        "tags": ["osint", "passive", "saas", "identity", "dns"],
    }

    target = OptString("", "Primary organization domain (e.g. example.com)", required=True)
    probe_login = OptString(
        "",
        "Login string for Microsoft realm probe (default: info@<target>)",
        required=False,
    )
    timeout = OptString("12", "HTTP/DNS timeout in seconds", required=False)
    scan_cert_subdomains = OptBool(
        True,
        "Query crt.sh for subdomains and extract IdP / collab host hints (okta, auth0, atlassian, slack, notion)",
        required=False,
    )
    max_cert_names = OptString("400", "Max certificate names to process from crt.sh", required=False)
    try_workspace_slugs = OptBool(
        True,
        "Best-effort HTTPS check for <apex>.slack.com and <apex>.atlassian.net",
        required=False,
    )
    output_file = OptString("", "Optional JSON output file", required=False)

    _CRT_HINTS = (
        (re.compile(r"([a-z0-9][a-z0-9.-]*)\.okta\.com$", re.I), "okta", "tenant_host"),
        (re.compile(r"([a-z0-9][a-z0-9.-]*)\.oktapreview\.com$", re.I), "okta_preview", "tenant_host"),
        (re.compile(r"([a-z0-9][a-z0-9.-]*)\.auth0\.com$", re.I), "auth0", "tenant_host"),
        (re.compile(r"([a-z0-9][a-z0-9.-]*)\.atlassian\.net$", re.I), "atlassian", "tenant_host"),
        (re.compile(r"([a-z0-9][a-z0-9.-]*)\.slack\.com$", re.I), "slack", "tenant_host"),
        (re.compile(r"([a-z0-9][a-z0-9.-]*)\.notion\.so$", re.I), "notion", "tenant_host"),
    )

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_domain(self, value):
        domain = str(value).strip().lower()
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/", 1)[0].strip(".")
        if "@" in domain:
            return None
        if not domain or "." not in domain:
            return None
        return domain

    def _dns(self, name, rtype, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            return [r.to_text().strip() for r in resolver.resolve(name, rtype)]
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

    def _classify_mx_txt(self, mx_records, txt_records):
        hints = []
        blob_mx = " ".join(mx_records).lower()
        blob_txt = " ".join(txt_records).lower()

        def add(provider, signal, detail=None):
            entry = {"provider": provider, "signal": signal}
            if detail:
                entry["detail"] = detail
            hints.append(entry)

        if "outlook.com" in blob_mx or "protection.outlook.com" in blob_mx:
            add("microsoft_365", "mx_outlook")
        if "spf.protection.outlook.com" in blob_txt or "include:spf.protection.outlook.com" in blob_txt:
            add("microsoft_365", "spf_exchange_online")
        if "google.com" in blob_mx or "l.google.com" in blob_mx:
            add("google_workspace", "mx_google")
        if "_spf.google.com" in blob_txt or "include:_spf.google.com" in blob_txt:
            add("google_workspace", "spf_google")
        if "pphosted.com" in blob_mx:
            add("proofpoint", "mx_proofpoint")
        if "mimecast.com" in blob_mx or "mimecast." in blob_mx:
            add("mimecast", "mx_mimecast")
        if "mailgun.org" in blob_mx:
            add("mailgun", "mx_mailgun")
        if "sendgrid.net" in blob_mx:
            add("sendgrid", "mx_sendgrid")
        if "zendesk.com" in blob_mx:
            add("zendesk", "mx_zendesk")
        if "intercom.io" in blob_mx or "intercom-mail.com" in blob_mx:
            add("intercom", "mx_intercom")
        if "okta.com" in blob_txt or "oktapreview.com" in blob_txt:
            add("okta", "spf_or_txt_reference")
        if "auth0.com" in blob_txt:
            add("auth0", "spf_or_txt_reference")
        if "atlassian.net" in blob_txt or "atlassian.com" in blob_txt:
            add("atlassian", "spf_or_txt_reference")
        if "mktomail.com" in blob_mx or "mkto" in blob_txt:
            add("marketo", "mail_infra")
        if "salesforce.com" in blob_mx or "salesforce" in blob_txt:
            add("salesforce", "mail_or_txt")

        return hints

    def _microsoft_getuserrealm(self, login_email, timeout_seconds):
        q = quote(login_email, safe="")
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login={q}"
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200:
            return {"error": "request_failed", "status_code": getattr(resp, "status_code", None)}
        try:
            return resp.json()
        except Exception:
            return {"error": "invalid_json"}

    def _microsoft_autodiscover(self, login_email, timeout_seconds):
        path = f"/autodiscover/autodiscover.json/v1.0/{quote(login_email, safe='@.')}"
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        for host in ("outlook.office365.com", "autodiscover-s.outlook.com"):
            try:
                self.target = host
                self.port = 443
                self.ssl = True
                resp = self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
                if resp and resp.status_code == 200:
                    try:
                        return {"host": host, "data": resp.json()}
                    except Exception:
                        return {"host": host, "raw": (resp.text or "")[:2000]}
            except Exception:
                continue
            finally:
                self.target = old_target
                self.port = old_port
                self.ssl = old_ssl
        return {}

    def _crtsh_names(self, domain, timeout_seconds, max_names):
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200:
            return []
        try:
            rows = resp.json()
        except Exception:
            return []
        names = []
        for row in rows or []:
            for key in ("name_value", "common_name"):
                val = row.get(key)
                if not val:
                    continue
                for part in str(val).split("\n"):
                    part = part.strip().lower().rstrip(".")
                    if part and "*" not in part:
                        names.append(part)
            if len(names) >= max_names * 4:
                break
        out = []
        seen = set()
        for n in names:
            if n in seen:
                continue
            seen.add(n)
            out.append(n)
            if len(out) >= max_names:
                break
        return out

    def _extract_ct_hints(self, names):
        found = []
        seen = set()
        for name in names:
            host = name.split(":")[0]
            for rx, provider, kind in self._CRT_HINTS:
                m = rx.search(host)
                if not m:
                    continue
                slug = m.group(1).lower()
                key = (provider, slug)
                if key in seen:
                    continue
                seen.add(key)
                found.append(
                    {
                        "provider": provider,
                        "kind": kind,
                        "slug": slug,
                        "host": host,
                    }
                )
        return found

    def _probe_slack_atlassian(self, apex, timeout_seconds):
        results = []
        slug = apex.split(".")[0].lower()
        if not slug or len(slug) < 2:
            return results
        for label, url in (
            ("slack_workspace", f"https://{slug}.slack.com/"),
            ("atlassian_cloud", f"https://{slug}.atlassian.net/"),
        ):
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                continue
            sc = resp.status_code
            if sc in (200, 301, 302, 303, 307, 308, 401, 403):
                results.append(
                    {
                        "guess": label,
                        "url": url,
                        "status_code": sc,
                        "note": "Heuristic slug from apex domain; verify manually.",
                    }
                )
        return results

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid_domain"}

        timeout_seconds = self._to_int(self.timeout, 12)
        max_cert = self._to_int(self.max_cert_names, 400)

        probe = str(self.probe_login).strip().lower()
        if not probe or "@" not in probe:
            probe = f"info@{domain}"

        print_info(f"SaaS / IdP discovery for {domain} (Microsoft probe login: {probe})")

        mx = self._dns(domain, "MX", timeout_seconds)
        txt = self._dns(domain, "TXT", timeout_seconds)
        dns_hints = self._classify_mx_txt(mx, txt)

        ms_realm = self._microsoft_getuserrealm(probe, timeout_seconds)
        ms_ad = self._microsoft_autodiscover(probe, timeout_seconds)

        ct_names = []
        ct_hints = []
        if self.scan_cert_subdomains:
            ct_names = self._crtsh_names(domain, timeout_seconds, max_cert)
            ct_hints = self._extract_ct_hints(ct_names)

        slug_probes = []
        if self.try_workspace_slugs:
            slug_probes = self._probe_slack_atlassian(domain, timeout_seconds)

        data = {
            "target": domain,
            "probe_login": probe,
            "mx": mx,
            "txt_sample": txt[:25] if len(txt) > 25 else txt,
            "dns_saas_hints": dns_hints,
            "microsoft_getuserrealm": ms_realm,
            "microsoft_autodiscover": ms_ad,
            "certificate_transparency": {
                "enabled": bool(self.scan_cert_subdomains),
                "names_considered": len(ct_names),
                "tenant_hints": ct_hints,
            },
            "heuristic_workspace_urls": slug_probes,
        }

        print_success(
            f"DNS hints: {len(dns_hints)} | CT tenant hints: {len(ct_hints)} | MS realm keys: {list(ms_realm.keys()) if isinstance(ms_realm, dict) else 'n/a'}"
        )

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as f:
                    json.dump(data, f, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("error"):
            return [], []

        root = data.get("target", self.target)
        nodes = [{"id": root, "label": root, "group": "domain", "icon": "🌐"}]
        edges = []

        for h in data.get("dns_saas_hints", [])[:30]:
            pid = f"dns_{h.get('provider','?')}_{h.get('signal','?')}"
            nodes.append({"id": pid, "label": h.get("provider", "?"), "group": "saas", "icon": "☁️"})
            edges.append({"from": root, "to": pid, "label": h.get("signal", "dns")})

        for t in data.get("certificate_transparency", {}).get("tenant_hints", [])[:40]:
            tid = f"ct_{t.get('provider')}_{t.get('slug')}"
            nodes.append({"id": tid, "label": f"{t.get('slug')} ({t.get('provider')})", "group": "idp", "icon": "🔑"})
            edges.append({"from": root, "to": tid, "label": "ct"})

        ms = data.get("microsoft_getuserrealm") or {}
        if isinstance(ms, dict) and ms.get("DomainName"):
            mid = f"msft_{ms.get('DomainName')}"
            nodes.append({"id": mid, "label": ms.get("DomainName"), "group": "microsoft", "icon": "📧"})
            edges.append({"from": root, "to": mid, "label": ms.get("NameSpaceType", "realm")})

        return nodes, edges
