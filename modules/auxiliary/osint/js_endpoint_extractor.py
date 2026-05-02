from kittysploit import *
import json
import re
from urllib.parse import urljoin, urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "JS Endpoint Extractor",
        "author": ["KittySploit Team"],
        "description": "Extract JS files and discover API endpoints/domains/keys from public client-side code.",
        "tags": ["osint", "passive", "web", "javascript"],
    }

    target = OptString("", "Target URL or domain", required=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    ENDPOINT_RX = re.compile(r"""(?:"|')((?:https?:\/\/[^\s"'<>]+)|(?:\/(?:api|v1|v2|graphql|rest)[^"']*))(?:"|')""", re.IGNORECASE)
    DOMAIN_RX = re.compile(r"""(?:"|')([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(?:"|')""", re.IGNORECASE)
    KEY_RX = re.compile(r"""(?i)(api[_-]?key|token|secret|client[_-]?secret)\s*[:=]\s*["']([^"']{8,})["']""")
    NOISE_ENDPOINT_EXT = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
        ".css", ".woff", ".woff2", ".ttf", ".map", ".pdf", ".mp4",
        ".mp3", ".avi", ".mov", ".zip", ".tar", ".gz",
    )
    NOISE_DOMAIN_MARKERS = (
        "googletagmanager.com", "google-analytics.com", "doubleclick.net",
        "gstatic.com", "cloudflare.com", "cdn.", "fonts.googleapis.com",
        "fonts.gstatic.com", "facebook.net", "intercom.io",
    )

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_base_url(self, value):
        v = str(value).strip()
        if not v:
            return None
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

    def _normalize_endpoint(self, endpoint, base_url):
        e = (endpoint or "").strip()
        if not e:
            return None
        if e.startswith("//"):
            e = "https:" + e
        if e.startswith("/"):
            e = urljoin(base_url, e)
        if not e.startswith(("http://", "https://")):
            return None

        low = e.lower()
        if "javascript:" in low or "data:" in low:
            return None
        if any(low.endswith(ext) for ext in self.NOISE_ENDPOINT_EXT):
            return None
        return e

    def _is_interesting_endpoint(self, endpoint):
        e = endpoint.lower()
        keywords = (
            "/api", "/graphql", "/v1", "/v2", "/auth", "/login",
            "/admin", "/token", "/oauth", "/user", "/account",
            "/internal", "/private",
        )
        return any(k in e for k in keywords)

    def _is_noise_domain(self, domain):
        d = (domain or "").lower()
        return any(m in d for m in self.NOISE_DOMAIN_MARKERS)

    def _fetch(self, url, timeout_seconds):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None, "", url
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # Temporarily map URL into Http_client option model.
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = (scheme == "https")
            r = self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
            )
            return r.status_code, r.text or "", r.url
        except Exception:
            return None, "", url
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _extract_js_urls(self, html, base_url):
        urls = set()
        for m in re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, flags=re.IGNORECASE):
            abs_url = urljoin(base_url, m.strip())
            if abs_url.startswith(("http://", "https://")):
                urls.add(abs_url)
        return sorted(urls)

    def run(self):
        base_url = self._normalize_base_url(self.target)
        if not base_url:
            print_error("target is required")
            return {"error": "target is required"}

        timeout_seconds = 10
        max_js = 20
        print_info(f"Extracting JS endpoints from {base_url}")

        status, html, final_url = self._fetch(base_url, timeout_seconds)
        if status is None or not html:
            print_error("Could not fetch target page")
            return {"error": "fetch_failed", "target": base_url}

        js_urls = self._extract_js_urls(html, final_url)[:max_js]
        print_info(f"JS files discovered: {len(js_urls)}")

        endpoints = set()
        domains = set()
        keys = []
        js_scanned = []

        for js in js_urls:
            st, body, fetched = self._fetch(js, timeout_seconds)
            if st is None or not body:
                continue
            js_scanned.append({"url": fetched, "status": st, "size": len(body)})

            for e in self.ENDPOINT_RX.findall(body):
                normalized = self._normalize_endpoint(e, final_url)
                if not normalized:
                    continue
                endpoints.add(normalized)

            for d in self.DOMAIN_RX.findall(body):
                if d and "." in d:
                    domains.add(d.lower())

            for kname, kval in self.KEY_RX.findall(body):
                keys.append({"name": kname, "value_preview": kval[:6] + "***", "source": fetched})

        # Keep external domains only (exclude target host).
        target_host = urlparse(final_url).hostname or ""
        external_domains = sorted(
            d for d in domains
            if d != target_host
            and not d.endswith("." + target_host)
            and not self._is_noise_domain(d)
        )

        all_endpoints = sorted(endpoints)
        interesting_endpoints = [e for e in all_endpoints if self._is_interesting_endpoint(e)]
        # Reduce noise: prefer semantically interesting endpoints first.
        if interesting_endpoints:
            selected_endpoints = interesting_endpoints[:160]
        else:
            selected_endpoints = all_endpoints[:120]

        findings = {
            "endpoints": selected_endpoints,
            "external_domains": external_domains[:200],
            "key_hints": keys[:100],
        }

        risk_score = 0
        signals = []
        if len(findings["endpoints"]) >= 20:
            risk_score += 2
            signals.append("many_client_exposed_endpoints")
        elif len(findings["endpoints"]) >= 8:
            risk_score += 1
            signals.append("multiple_client_exposed_endpoints")
        if len(findings["external_domains"]) >= 8:
            risk_score += 2
            signals.append("many_external_third_party_domains")
        if len(findings["key_hints"]) > 0:
            risk_score += 3
            signals.append("possible_secret_literals_in_js")

        risk_level = "LOW" if risk_score <= 2 else ("MEDIUM" if risk_score <= 4 else "HIGH")

        data = {
            "target": final_url,
            "js_files": js_scanned,
            "count_js": len(js_scanned),
            "count_endpoints": len(findings["endpoints"]),
            "count_endpoints_interesting": len(interesting_endpoints),
            "count_external_domains": len(findings["external_domains"]),
            "count_key_hints": len(findings["key_hints"]),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "signals": signals,
            "findings": findings,
        }

        print_success(
            f"JS scan done: js={data['count_js']} endpoints={data['count_endpoints']} "
            f"(interesting={data['count_endpoints_interesting']}) "
            f"external_domains={data['count_external_domains']} key_hints={data['count_key_hints']}"
        )
        print_info(f"Risk: {risk_level} ({risk_score})")

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
        nodes, edges = [], []
        for i, e in enumerate(data.get("findings", {}).get("endpoints", [])[:15]):
            nid = f"api_{i}_{target}"
            nodes.append({"id": nid, "label": e[:60], "group": "hostname", "icon": "🧩"})
            edges.append({"from": target, "to": nid, "label": "endpoint"})
        for i, d in enumerate(data.get("findings", {}).get("external_domains", [])[:12]):
            nid = f"extdom_{i}_{target}"
            nodes.append({"id": nid, "label": d, "group": "domain", "icon": "🌍"})
            edges.append({"from": target, "to": nid, "label": "external"})
        return nodes, edges
