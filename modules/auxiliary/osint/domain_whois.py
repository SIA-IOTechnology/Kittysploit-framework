

from kittysploit import *
import importlib
from datetime import datetime

class Module(Auxiliary):
    
    __info__ = {
        'name': 'Domain WHOIS',
        'author': ['KittySploit Team'],
        'description': 'Retrieves domain registration details using standard WHOIS protocol.',
        'tags': ['osint', 'passive', 'domain'],
    }
        
    target = OptString("", "The target domain name", required=True)

    def _first(self, value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _pick(self, source, *keys):
        for key in keys:
            if isinstance(source, dict):
                if key in source and source.get(key) is not None:
                    return source.get(key)
            else:
                if hasattr(source, key):
                    val = getattr(source, key)
                    if val is not None:
                        return val
        return None

    def run(self):
        target = str(self.target).strip()

        try:
            w = None
            registrar = None
            cdate = None
            edate = None
            emails = []
            name_servers = []
            org = None
            country = None

            whois = None
            import_error = None
            try:
                whois = importlib.import_module("whois")
            except Exception as ie:
                import_error = str(ie)

            if whois is not None and hasattr(whois, "whois") and callable(getattr(whois, "whois")):
                # python-whois
                w = whois.whois(target)
            elif whois is not None and hasattr(whois, "query") and callable(getattr(whois, "query")):
                # alternate "whois" wrappers
                w = whois.query(target)
            else:
                # Fallback: pythonwhois package API
                try:
                    pythonwhois = importlib.import_module("pythonwhois")
                    if hasattr(pythonwhois, "get_whois") and callable(getattr(pythonwhois, "get_whois")):
                        w = pythonwhois.get_whois(target)
                except Exception:
                    pass

            if not w:
                if whois is None:
                    err = f"WHOIS package unavailable (import error: {import_error or 'unknown'})"
                else:
                    module_file = getattr(whois, "__file__", "unknown")
                    err = (
                        "Unsupported whois package API for module "
                        f"'{module_file}' (missing whois/query/get_whois). "
                        "Install python-whois: pip install -U python-whois"
                    )
                print_error(err)
                return {"error": err}

            registrar = self._pick(w, "registrar")
            cdate = self._pick(w, "creation_date", "creation", "created")
            edate = self._pick(w, "expiration_date", "expires_date", "expiration")
            emails = self._pick(w, "emails")
            name_servers = self._pick(w, "name_servers", "nameservers")
            org = self._pick(w, "org", "organization")
            country = self._pick(w, "country")

            # pythonwhois dict normalization
            if isinstance(w, dict):
                registrar = registrar or self._pick(w, "registrar")
                if not registrar:
                    reg = self._pick(w, "registrar")
                    if isinstance(reg, list) and reg:
                        registrar = reg[0]

                contacts = self._pick(w, "contacts") or {}
                if not org and isinstance(contacts, dict):
                    registrant = contacts.get("registrant") or {}
                    if isinstance(registrant, dict):
                        org = registrant.get("organization") or registrant.get("name")
                        country = country or registrant.get("country")
                        if not emails:
                            emails = registrant.get("email")

                raw_ns = self._pick(w, "nameservers", "name_servers")
                if raw_ns and not name_servers:
                    name_servers = raw_ns

            cdate = self._first(cdate)
            edate = self._first(edate)
            emails = self._as_list(emails)
            name_servers = self._as_list(name_servers)

            data = {
                "registrar": registrar,
                "creation_date": str(cdate) if cdate else None,
                "expiration_date": str(edate) if edate else None,
                "emails": [str(e) for e in emails if e],
                "name_servers": [str(ns) for ns in name_servers if ns],
                "org": org,
                "country": country,
            }

            print_success(f"WHOIS data retrieved for {target}")
            return data

        except Exception as e:
            print_error(f"WHOIS lookup failed: {e}")
            return {"error": str(e)}

    def get_graph_nodes(self, data):
        """
        Returns visual graph elements based on run() output.
        Specific to KittyOSINT visualization.
        """
        target = self.target
        nodes = []
        edges = []
        
        if "error" in data: return [], []
        
        # Registrar Node
        if data.get("registrar"):
            rid = f"reg_{data['registrar']}"
            nodes.append({"id": rid, "label": str(data['registrar']), "group": "registrar", "icon": "🏢"})
            edges.append({"from": target, "to": rid, "label": "registered via"})
            
        # Email Nodes
        emails = data.get("emails", [])
        if isinstance(emails, str): emails = [emails]
        for email in emails:
            eid = f"email_{email}"
            nodes.append({"id": eid, "label": str(email), "group": "email", "icon": "📧"})
            edges.append({"from": target, "to": eid, "label": "contact"})
            
        # Name Server Nodes
        ns_list = data.get("name_servers", [])
        if isinstance(ns_list, str): ns_list = [ns_list]
        for ns in ns_list:
            nid = f"ns_{ns}"
            nodes.append({"id": nid, "label": str(ns), "group": "nameserver", "icon": "📡"})
            edges.append({"from": target, "to": nid, "label": "NS"})
            
        return nodes, edges
