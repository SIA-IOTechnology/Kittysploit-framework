
from kittysploit import *
import dns.resolver

class Module(Auxiliary):

    __info__ = {
        'name': 'DNS Recon',
        'author': ['KittySploit Team'],
        'description': 'Retrieves A, MX, NS records using DNS resolver.',
        'tags': ['osint', 'passive', 'dns'],
    }
        
    target = OptString("", "The target domain name", required=True)

    def run(self):
        target = self.target
        data = {}
        
        try:
            resolver = dns.resolver.Resolver()
            for rtype in ['A', 'MX', 'NS', 'TXT']:
                try:
                    answers = resolver.resolve(target, rtype)
                    data[rtype] = [r.to_text() for r in answers]
                    print_success(f"Found {len(data[rtype])} {rtype} records for {target}")
                except Exception:
                    data[rtype] = []
        except Exception as e:
            print_error(f"DNS lookup failed: {e}")
            data['error'] = str(e)
            
        return data

    def get_graph_nodes(self, data):
        target = self.target
        nodes = []
        edges = []
        
        if "error" in data: return [], []
        
        # A Records (IPs)
        for ip in data.get('A', []):
            label = ip
            nid = f"ip_{ip}"
            nodes.append({"id": nid, "label": label, "group": "ip", "icon": "🖥️"})
            edges.append({"from": target, "to": nid, "label": "A Record"})
            
        # MX Records (Mail Servers)
        for mx in data.get('MX', []):
            label = mx.split()[-1] if ' ' in mx else mx
            nid = f"mx_{label}"
            nodes.append({"id": nid, "label": label, "group": "mailserver", "icon": "📨"})
            edges.append({"from": target, "to": nid, "label": "MX Record"})
            
        # NS Records
        for ns in data.get('NS', []):
            nid = f"ns_{ns}"
            nodes.append({"id": nid, "label": ns, "group": "nameserver", "icon": "📡"})
            edges.append({"from": target, "to": nid, "label": "NS Record"})
            
        return nodes, edges
