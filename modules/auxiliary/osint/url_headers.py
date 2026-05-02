
from kittysploit import *
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'URL Headers & Tech',
        'author': ['KittySploit Team'],
        'description': 'Fetches HTTP headers and detects server/tech hints from a URL.',
        'tags': ['osint', 'passive', 'http', 'url'],
    }

    target = OptString("", "The target URL (e.g. https://example.com)", required=True)

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

    def run(self):
        target = self.target.strip()
        if "@" in target and not target.startswith(("http://", "https://")):
            print_error("Invalid URL target: email-like values are not accepted here")
            return {"error": "invalid url target", "url": target}
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        data = {"url": target, "headers": {}, "tech": [], "status_code": None, "transport": "https"}

        resp = self._http_get_url(target, 15)
        if not resp:
            fallback_url = target.replace("https://", "http://", 1) if target.startswith("https://") else target
            resp = self._http_get_url(fallback_url, 15)
            if resp:
                target = fallback_url
                data["url"] = fallback_url
                data["transport"] = "http_fallback"
                data["ssl_warning"] = "https failed, fallback to http"
        if not resp:
            print_error("HTTP request failed")
            return {"error": "request_failed", "url": target, "transport": "failed"}

        try:
            data["status_code"] = resp.status_code
            data["final_url"] = resp.url

            # Normalize header names to lowercase for consistent output
            for k, v in resp.headers.items():
                data["headers"][k] = v

            # Basic tech hints from headers
            tech = []
            server = resp.headers.get("Server")
            if server:
                tech.append(f"Server: {server}")
            x_powered = resp.headers.get("X-Powered-By")
            if x_powered:
                tech.append(f"X-Powered-By: {x_powered}")
            x_aspnet = resp.headers.get("X-AspNet-Version")
            if x_aspnet:
                tech.append(f"X-AspNet-Version: {x_aspnet}")
            x_generator = resp.headers.get("X-Generator")
            if x_generator:
                tech.append(f"X-Generator: {x_generator}")
            via = resp.headers.get("Via")
            if via:
                tech.append(f"Via: {via}")

            # Optional: detect from body (lightweight)
            ctype = resp.headers.get("Content-Type", "")
            if "wordpress" in ctype or "wp-" in resp.text[:4096].lower():
                tech.append("WordPress")
            if "django" in resp.text[:4096].lower() or "csrfmiddlewaretoken" in resp.text[:4096].lower():
                tech.append("Django")
            if "laravel" in resp.text[:4096].lower():
                tech.append("Laravel")

            data["tech"] = tech
            print_success(f"Headers retrieved for {target} (HTTP {resp.status_code})")
            return data
        except Exception as e:
            print_error(f"URL headers failed: {e}")
            return {"error": str(e), "url": target}

    def get_graph_nodes(self, data):
        target = self.target
        nodes = []
        edges = []

        if "error" in data:
            return [], []

        url = data.get("final_url") or data.get("url") or target
        root_id = f"url_{url}"
        nodes.append({"id": root_id, "label": url, "group": "hostname", "icon": "🌐"})
        edges.append({"from": target, "to": root_id, "label": "http"})

        limit = 12
        for i, t in enumerate(data.get("tech", [])[:limit]):
            nid = f"tech_{i}_{url}"
            nodes.append({"id": nid, "label": t[:50], "group": "generic", "icon": "⚙️"})
            edges.append({"from": root_id, "to": nid, "label": "tech"})

        if data.get("status_code"):
            nid = f"status_{url}"
            nodes.append({"id": nid, "label": f"HTTP {data['status_code']}", "group": "generic", "icon": "📡"})
            edges.append({"from": root_id, "to": nid, "label": "status"})

        return nodes, edges
