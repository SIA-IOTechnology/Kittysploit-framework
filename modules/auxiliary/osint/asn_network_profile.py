from kittysploit import *
import json
import ipaddress
import dns.resolver
from lib.protocols.http.http_client import Http_client
from urllib.parse import urlparse


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "ASN Network Profile",
        "author": ["KittySploit Team"],
        "description": "Profile ASN/network context from a domain or IPv4 target (ASN, org, geo, prefixes).",
        "tags": ["osint", "passive", "asn", "network"],
    }

    target = OptString("", "Target domain or IPv4", required=True)
    timeout = OptString("8", "HTTP/DNS timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _resolve_ip(self, target, timeout_seconds):
        t = str(target).strip().lower()
        try:
            ipaddress.IPv4Address(t)
            return t
        except Exception:
            pass
        # domain resolution
        t = t.replace("https://", "").replace("http://", "").split("/", 1)[0]
        if "@" in t:
            return None
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            ans = resolver.resolve(t, "A")
            for r in ans:
                return r.to_text().strip()
        except Exception:
            return None
        return None

    def _ip_api_profile(self, ip, timeout_seconds):
        # ip-api provides ASN string and network org context.
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,reverse,query"
        try:
            r = self._http_get_url(url, timeout_seconds)
            if not r:
                return None
            j = r.json()
            if j.get("status") != "success":
                return None
            as_field = j.get("as", "")
            asn = ""
            if as_field.startswith("AS"):
                asn = as_field.split()[0]
            return {
                "ip": j.get("query", ip),
                "asn": asn,
                "as_raw": as_field,
                "as_name": j.get("asname"),
                "org": j.get("org"),
                "isp": j.get("isp"),
                "reverse": j.get("reverse"),
                "country": j.get("country"),
                "country_code": j.get("countryCode"),
                "region": j.get("regionName"),
                "city": j.get("city"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
            }
        except Exception:
            return None

    def _bgpview_asn_meta(self, asn, timeout_seconds):
        if not asn:
            return {"asn_meta": {}, "prefixes_v4": []}
        asn_num = asn.upper().replace("AS", "").strip()
        meta = {}
        prefixes = []
        try:
            url = f"https://api.bgpview.io/asn/{asn_num}"
            r = self._http_get_url(url, timeout_seconds)
            if not r:
                return {"asn_meta": {}, "prefixes_v4": []}
            j = r.json() if r.status_code == 200 else {}
            data = j.get("data", {})
            meta = {
                "asn": data.get("asn"),
                "name": data.get("name"),
                "description_short": data.get("description_short"),
                "country_code": data.get("country_code"),
                "rir_name": data.get("rir_name"),
            }
        except Exception:
            pass

        try:
            url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
            r = self._http_get_url(url, timeout_seconds)
            if not r:
                return {"asn_meta": meta, "prefixes_v4": prefixes}
            j = r.json() if r.status_code == 200 else {}
            pv4 = (j.get("data", {}) or {}).get("ipv4_prefixes", [])
            prefixes = [
                {
                    "prefix": p.get("prefix"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "country_code": p.get("country_code"),
                }
                for p in pv4[:80]
            ]
        except Exception:
            pass
        return {"asn_meta": meta, "prefixes_v4": prefixes}

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
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def run(self):
        timeout_seconds = self._to_int(self.timeout, 8)
        target = str(self.target).strip()
        ip = self._resolve_ip(target, timeout_seconds)
        if not ip:
            print_error("Could not resolve target to IPv4")
            return {"error": "ip_resolution_failed", "target": target}

        profile = self._ip_api_profile(ip, timeout_seconds)
        if not profile:
            print_error("Could not retrieve ASN profile")
            return {"error": "asn_profile_failed", "target": target, "ip": ip}

        bgp = self._bgpview_asn_meta(profile.get("asn"), timeout_seconds)
        data = {
            "target": target,
            "ip": ip,
            "profile": profile,
            "asn_meta": bgp.get("asn_meta", {}),
            "prefixes_v4": bgp.get("prefixes_v4", []),
            "count_prefixes_v4": len(bgp.get("prefixes_v4", [])),
        }

        print_success(
            f"ASN profile: {profile.get('asn', 'N/A')} {profile.get('org', '')} "
            f"| prefixes_v4={data['count_prefixes_v4']}"
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
        target = data.get("target", self.target)
        ip = data.get("ip", "")
        profile = data.get("profile", {})
        nodes, edges = [], []

        if ip:
            nid = f"ip_{ip}"
            nodes.append({"id": nid, "label": ip, "group": "ip", "icon": "🖥️"})
            edges.append({"from": target, "to": nid, "label": "resolved_ip"})
        else:
            nid = target

        asn = profile.get("asn")
        if asn:
            aid = f"asn_{asn}"
            nodes.append({"id": aid, "label": f"{asn} {profile.get('org', '')}".strip(), "group": "asn", "icon": "🌐"})
            edges.append({"from": nid, "to": aid, "label": "asn"})

        if profile.get("isp"):
            iid = f"isp_{profile.get('isp')}"
            nodes.append({"id": iid, "label": profile.get("isp"), "group": "organization", "icon": "🏢"})
            edges.append({"from": nid, "to": iid, "label": "isp"})

        loc = ", ".join([x for x in [profile.get("city"), profile.get("region"), profile.get("country")] if x])
        if loc:
            lid = f"loc_{ip}"
            nodes.append({"id": lid, "label": loc, "group": "location", "icon": "📍"})
            edges.append({"from": nid, "to": lid, "label": "location"})

        for i, p in enumerate(data.get("prefixes_v4", [])[:12]):
            pid = f"pfx_{i}_{ip}"
            nodes.append({"id": pid, "label": p.get("prefix", ""), "group": "generic", "icon": "🧭"})
            edges.append({"from": nid, "to": pid, "label": "prefix"})

        return nodes, edges
