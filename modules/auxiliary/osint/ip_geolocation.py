
from kittysploit import *
import requests
import ipaddress

class Module(Auxiliary):
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

    def run(self):
        target = self.target.strip()
        data = {}

        # Validate IPv4 strictly and skip gracefully when target is not an IP.
        try:
            ipaddress.IPv4Address(target)
        except Exception:
            print_status(f"Skipping geolocation: target is not an IPv4 address ({target})")
            return {"skipped": True, "reason": "target is not an IPv4 address", "ip": target}

        try:
            # ip-api.com free JSON endpoint (45 req/min)
            url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            j = resp.json()

            if j.get("status") != "success":
                msg = j.get("message", "Unknown error")
                print_error(f"ip-api error: {msg}")
                return {"error": msg, "ip": target}

            data = {
                "ip": j.get("query", target),
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
        except requests.RequestException as e:
            print_error(f"Geolocation request failed: {e}")
            return {"error": str(e), "ip": target}
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
