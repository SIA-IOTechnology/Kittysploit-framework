
from kittysploit import *
import ipaddress
import socket
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):
    """
    IP geolocation and ISP info for KittyOSINT (ip-api.com, free tier).
    """

    __info__ = {
        'name': 'IP Geolocation',
        'author': ['KittySploit Team'],
        'description': 'Retrieves geolocation, ISP and ASN for an IP address (ip-api.com).',
        'tags': ['osint', 'passive', 'ip', 'geolocation'],
    }

    target = OptString("", "The target IP address", required=True)

    def _http_get_url(self, url, timeout_seconds):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        scheme = (parsed.scheme or "http").lower()
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
        data = {}
        original_target = target

        # Accept domains by resolving to IPv4 before geolocation lookup.
        try:
            ipaddress.IPv4Address(target)
        except Exception:
            try:
                resolved = socket.gethostbyname(target)
                ipaddress.IPv4Address(resolved)
                print_status(f"Resolved domain {target} -> {resolved}")
                target = resolved
            except Exception:
                print_status(f"Skipping geolocation: target is not an IPv4 address ({target})")
                return {"skipped": True, "reason": "target is not an IPv4 address", "ip": target}

        try:
            # ip-api.com free JSON endpoint (45 req/min)
            url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            resp = self._http_get_url(url, 10)
            if not resp:
                raise Exception("HTTP request failed")
            if resp.status_code != 200:
                raise Exception(f"HTTP {resp.status_code}")
            j = resp.json()

            if j.get("status") != "success":
                msg = j.get("message", "Unknown error")
                print_error(f"ip-api error: {msg}")
                return {"error": msg, "ip": target}

            data = {
                "ip": j.get("query", target),
                "input_target": original_target,
                "country": j.get("country"),
                "country_code": j.get("countryCode"),
                "region": j.get("regionName"),
                "city": j.get("city"),
                "zip": j.get("zip"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
                "timezone": j.get("timezone"),
                "isp": j.get("isp"),
                "org": j.get("org"),
                "as": j.get("as"),
            }
            print_success(f"Geolocation: {target} -> {data.get('city')}, {data.get('country')}")
            return data
        except Exception as e:
            print_error(f"Geolocation failed: {e}")
            return {"error": str(e), "ip": target}

    def get_graph_nodes(self, data):
        target = self.target
        nodes = []
        edges = []

        if "error" in data or data.get("skipped"):
            return [], []

        ip = data.get("ip", target)
        loc_parts = [data.get("city"), data.get("region"), data.get("country")]
        location = ", ".join(p for p in loc_parts if p)
        if location:
            nid = f"loc_{ip}"
            nodes.append({"id": nid, "label": location, "group": "location", "icon": "📍"})
            edges.append({"from": ip, "to": nid, "label": "location"})
        if data.get("isp"):
            nid = f"isp_{data['isp']}"
            nodes.append({"id": nid, "label": data["isp"], "group": "isp", "icon": "🏢"})
            edges.append({"from": ip, "to": nid, "label": "ISP"})
        if data.get("as"):
            nid = f"as_{data['as']}"
            nodes.append({"id": nid, "label": data["as"], "group": "asn", "icon": "🌐"})
            edges.append({"from": ip, "to": nid, "label": "AS"})

        return nodes, edges
