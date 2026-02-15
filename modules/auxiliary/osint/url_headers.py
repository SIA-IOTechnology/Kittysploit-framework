
from kittysploit import *
import requests
import re

class Module(Auxiliary):

    __info__ = {
        'name': 'URL Headers & Tech',
        'author': ['KittySploit Team'],
        'description': 'Fetches HTTP headers and detects server/tech hints from a URL.',
        'tags': ['osint', 'passive', 'http', 'url'],
    }

    target = OptString("", "The target URL (e.g. https://example.com)", required=True)

    def run(self):
        target = self.target.strip()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        data = {"url": target, "headers": {}, "tech": [], "status_code": None}

        try:
            resp = requests.get(target, timeout=15, allow_redirects=True)
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
        except requests.RequestException as e:
            print_error(f"HTTP request failed: {e}")
            return {"error": str(e), "url": target}
        except Exception as e:
            print_error(f"URL headers failed: {e}")
            return {"error": str(e), "url": target}

    def get_graph_nodes(self, data):
        target = self.target
        nodes = []
        edges = []

        if "error" in data:
            return [], []

        url = data.get("url") or data.get("final_url") or target
        limit = 12
        for i, t in enumerate(data.get("tech", [])[:limit]):
            nid = f"tech_{i}_{url}"
            nodes.append({"id": nid, "label": t[:50], "group": "tech", "icon": "⚙️"})
            edges.append({"from": url, "to": nid, "label": "tech"})

        if data.get("status_code"):
            nid = f"status_{url}"
            nodes.append({"id": nid, "label": f"HTTP {data['status_code']}", "group": "status", "icon": "📡"})
            edges.append({"from": url, "to": nid, "label": "status"})

        return nodes, edges
