
from kittysploit import *
import sys
import os
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Crt.sh Enumeration',
        'author': ['KittySploit Team'],
        'description': 'Find subdomains via Cert Transparency (crt.sh).',
        'tags': ['osint', 'passive', 'subdomains'],
        }
        
    target = OptString("", "The target domain name", required=True)

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
        target = self.target
        subdomains = set()
        data = {}
        
        try:
            url = f"https://crt.sh/?q=%25.{target}&output=json"
            resp = self._http_get_url(url, 10)
            if not resp:
                raise Exception("HTTP request failed")
            if resp.status_code == 200:
                results = resp.json()
                for entry in results:
                    name = entry.get('name_value')
                    if name:
                        subnames = name.split('\n')
                        for s in subnames:
                            if '*' not in s and s.endswith(target):
                                subdomains.add(s)
            
            data = {"count": len(subdomains), "subdomains": list(subdomains)}
            print_success(f"Found {len(subdomains)} subdomains via crt.sh")
            return data
            
        except Exception as e:
            print_error(f"Crt.sh lookup failed: {e}")
            data = {"error": str(e)}
            
        return data

    def get_graph_nodes(self, data):
        target = self.target
        nodes = []
        edges = []
        
        if "error" in data: return [], []
        
        limit = 20 # Limit visible nodes to avoid clutter
        subdomains = data.get("subdomains", [])
        
        for i, sub in enumerate(subdomains):
            if i >= limit: break
            nid = f"sub_{sub}"
            nodes.append({"id": nid, "label": sub, "group": "subdomain", "icon": "🌐"})
            edges.append({"from": target, "to": nid, "label": "cert"})
            
        if len(subdomains) > limit:
            remaining = len(subdomains) - limit
            nid = f"more_{target}"
            nodes.append({"id": nid, "label": f"+{remaining} more...", "group": "meta", "icon": "➕"})
            edges.append({"from": target, "to": nid, "label": "hidden"})
            
        return nodes, edges
