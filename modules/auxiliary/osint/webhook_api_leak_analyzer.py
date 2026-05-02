from kittysploit import *
import json
import re
from urllib.parse import urljoin, urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Webhook and Forgotten API Leak Analyzer",
        "author": ["KittySploit Team"],
        "description": "Discover exposed webhook/API endpoints from JavaScript files and perform lightweight validation.",
        "tags": ["osint", "web", "api", "webhook"],
    }

    target = OptString("", "Target URL or domain", required=True)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    JS_SRC_RX = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
    ENDPOINT_RX = re.compile(
        r"""(?:"|')((?:https?:\/\/[^\s"'<>]+)|(?:\/(?:api|v1|v2|graphql|webhook|hooks|internal)[^"']*))(?:"|')""",
        re.IGNORECASE,
    )

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_target_url(self, target):
        t = str(target).strip()
        if not t:
            return None
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        return t

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
            return self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _head_or_get_status(self, endpoint, timeout_seconds):
        parsed = urlparse(endpoint)
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
            r = self.http_request("HEAD", path=path, timeout=timeout_seconds, allow_redirects=True)
            return r.status_code
        except Exception:
            try:
                r2 = self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
                return r2.status_code
            except Exception:
                return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _interesting(self, endpoint):
        e = endpoint.lower()
        keywords = [
            "/webhook", "/hooks", "/graphql", "/api", "/internal", "/admin", "/token",
            "/auth", "/private", "/callback",
        ]
        return any(k in e for k in keywords)

    def run(self):
        base_url = self._normalize_target_url(self.target)
        if not base_url:
            print_error("target is required")
            return {"error": "target is required"}
        timeout_seconds = self._to_int(self.timeout, 10)

        print_info(f"Analyzing forgotten API/webhook exposure from {base_url}")
        page = self._http_get_url(base_url, timeout_seconds)
        if not page or page.status_code != 200 or not page.text:
            print_error("Could not fetch target page")
            return {"error": "fetch_failed", "target": base_url}

        final_url = page.url
        js_urls = sorted({
            urljoin(final_url, src.strip())
            for src in self.JS_SRC_RX.findall(page.text)
            if src.strip()
        })[:30]
        endpoints = set()
        for js in js_urls:
            r = self._http_get_url(js, timeout_seconds)
            if not r or r.status_code != 200 or not r.text:
                continue
            for m in self.ENDPOINT_RX.findall(r.text):
                candidate = m.strip()
                if candidate.startswith("/"):
                    candidate = urljoin(final_url, candidate)
                if candidate.startswith("//"):
                    candidate = "https:" + candidate
                if candidate.startswith(("http://", "https://")):
                    endpoints.add(candidate)

        interesting = [e for e in sorted(endpoints) if self._interesting(e)]
        validated = []
        for endpoint in interesting[:80]:
            st = self._head_or_get_status(endpoint, timeout_seconds)
            risk = "low"
            if st in (200, 201, 202, 204):
                risk = "high"
            elif st in (401, 403):
                risk = "medium"
            validated.append({
                "endpoint": endpoint,
                "status": st,
                "risk": risk,
            })

        high = [x for x in validated if x.get("risk") == "high"]
        risk_score = min(10, len(high) + (1 if len(interesting) >= 15 else 0))
        risk_level = "LOW" if risk_score <= 2 else ("MEDIUM" if risk_score <= 5 else "HIGH")
        data = {
            "target": final_url,
            "count_js": len(js_urls),
            "count_endpoints": len(interesting),
            "count_validated": len(validated),
            "count_high_risk": len(high),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "endpoints": validated,
        }
        print_success(
            f"Webhook/API analysis done: endpoints={data['count_endpoints']} high={data['count_high_risk']} risk={risk_level}"
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
        root = data.get("target", self.target)
        nodes, edges = [], []
        for i, row in enumerate(data.get("endpoints", [])[:20]):
            nid = f"apiw_{i}"
            icon = "🧷" if row.get("risk") == "high" else "🔗"
            nodes.append({
                "id": nid,
                "label": row.get("endpoint", "")[:72],
                "group": "endpoint",
                "icon": icon,
            })
            edges.append({"from": root, "to": nid, "label": str(row.get("status"))})
        return nodes, edges
