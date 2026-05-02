from kittysploit import *
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "SSL TLS Certificate Change Tracker",
        "author": ["KittySploit Team"],
        "description": "Track certificate transparency changes and trust-chain anomalies for a domain.",
        "tags": ["osint", "tls", "ssl", "certificate", "ct"],
    }

    target = OptString("", "Target domain", required=True)
    limit = OptString("50", "Maximum CT entries to keep", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_domain(self, value):
        v = str(value).strip().lower()
        v = v.replace("https://", "").replace("http://", "")
        v = v.split("/", 1)[0].strip(".")
        if not v or "." not in v:
            return None
        return v

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

    def _parse_ct_time(self, value):
        if not value:
            return None
        # crt.sh formats vary, keep best effort.
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value[:19], fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
        return None

    def _chain_risk(self, entries):
        score = 0
        signals = []
        if len(entries) >= 50:
            score += 2
            signals.append("high_certificate_churn")
        issuers = {str(e.get("issuer_name", "")).lower() for e in entries if e.get("issuer_name")}
        if len(issuers) >= 4:
            score += 2
            signals.append("many_distinct_issuers")
        wildcard = [e for e in entries if "*" in str(e.get("name_value", ""))]
        if wildcard:
            score += 1
            signals.append("wildcard_certificates_present")
        recent = 0
        now = datetime.now(timezone.utc)
        for e in entries:
            ts = self._parse_ct_time(e.get("entry_timestamp"))
            if ts and (now - ts).days <= 14:
                recent += 1
        if recent >= 5:
            score += 2
            signals.append("recent_certificate_wave")
        return min(10, score), signals

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid target"}
        timeout_seconds = self._to_int(self.timeout, 10)
        limit = self._to_int(self.limit, 50)

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        print_info(f"Tracking CT certificate changes for {domain}")
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200:
            print_error("Failed to query crt.sh")
            return {"error": "ct_query_failed", "target": domain}
        try:
            rows = resp.json()
        except Exception:
            print_error("Invalid CT response")
            return {"error": "ct_parse_failed", "target": domain}

        entries = []
        seen = set()
        for row in rows:
            key = f"{row.get('id')}:{row.get('issuer_name')}:{row.get('name_value')}"
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "id": row.get("id"),
                "issuer_name": row.get("issuer_name"),
                "name_value": row.get("name_value"),
                "entry_timestamp": row.get("entry_timestamp"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
            })
        entries = entries[:limit]

        risk_score, signals = self._chain_risk(entries)
        risk_level = "LOW" if risk_score <= 2 else ("MEDIUM" if risk_score <= 5 else "HIGH")
        data = {
            "target": domain,
            "count_certificates": len(entries),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "signals": signals,
            "certificates": entries,
        }
        print_success(
            f"CT tracking done: certificates={data['count_certificates']} risk={risk_level}"
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
        for i, cert in enumerate(data.get("certificates", [])[:20]):
            nid = f"cert_{i}_{root}"
            nodes.append({
                "id": nid,
                "label": f"{cert.get('issuer_name', 'issuer')} -> {str(cert.get('name_value', ''))[:40]}",
                "group": "certificate",
                "icon": "🔐",
            })
            edges.append({"from": root, "to": nid, "label": "ct"})
        return nodes, edges
