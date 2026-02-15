
from kittysploit import *
import dns.resolver
import dns.reversename
import ipaddress

class Module(Auxiliary):

    __info__ = {
        'name': 'IP Reverse DNS',
        'author': ['KittySploit Team'],
        'description': 'Retrieves PTR (reverse DNS) hostnames for an IP address.',
        'tags': ['osint', 'passive', 'dns', 'ip'],
    }

    target = OptString("", "The target IP address", required=True)

    def run(self):
        target = self.target.strip()
        data = {}

        # Avoid hard errors when this IP-only module is executed on a domain target.
        try:
            ipaddress.IPv4Address(target)
        except Exception:
            print_status(f"Skipping reverse DNS: target is not an IPv4 address ({target})")
            return {"skipped": True, "reason": "target is not an IPv4 address", "ip": target}

        try:
            rev = dns.reversename.from_address(target)
            answers = dns.resolver.resolve(rev, "PTR")
            ptr_records = [r.to_text().rstrip(".") for r in answers]
            data = {
                "ip": target,
                "count": len(ptr_records),
                "hostnames": ptr_records,
            }
            print_success(f"Reverse DNS: {target} -> {len(ptr_records)} hostname(s)")
            return data
        except dns.resolver.NXDOMAIN:
            data = {"ip": target, "count": 0, "hostnames": [], "message": "No PTR record"}
            print_status(f"No PTR record for {target}")
            return data
        except Exception as e:
            print_error(f"Reverse DNS lookup failed: {e}")
            return {"error": str(e), "ip": target}

    def get_graph_nodes(self, data):
        target = self.target
        nodes = []
        edges = []

        if "error" in data or data.get("skipped"):
            return [], []

        ip = data.get("ip", target)
        hostnames = data.get("hostnames", [])
        limit = 15
        for i, h in enumerate(hostnames):
            if i >= limit:
                break
            nid = f"ptr_{h}"
            nodes.append({"id": nid, "label": h, "group": "hostname", "icon": "🔗"})
            edges.append({"from": ip, "to": nid, "label": "PTR"})

        if len(hostnames) > limit:
            nid = f"more_ptr_{ip}"
            nodes.append({"id": nid, "label": f"+{len(hostnames) - limit} more...", "group": "meta", "icon": "➕"})
            edges.append({"from": ip, "to": nid, "label": "hidden"})

        return nodes, edges
