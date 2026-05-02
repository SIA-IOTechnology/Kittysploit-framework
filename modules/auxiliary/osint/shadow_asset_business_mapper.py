from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Shadow Asset Business Mapper",
        "author": ["KittySploit Team"],
        "description": "Discover shadow assets and map them to business risk contexts.",
        "tags": ["osint", "asset-discovery", "shadow-it", "business-risk"],
    }

    target = OptString("", "Target domain (example.com)", required=True)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    max_subdomains = OptString("80", "Maximum subdomains to analyze", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    BUSINESS_KEYWORDS = {
        "payment": ["pay", "billing", "checkout", "stripe", "invoice", "wallet"],
        "authentication": ["auth", "sso", "login", "oauth", "idp", "mfa"],
        "customer_data": ["crm", "customer", "profile", "account", "user", "client"],
        "operations": ["admin", "internal", "ops", "monitor", "grafana", "kibana"],
        "development": ["dev", "staging", "test", "qa", "sandbox", "ci", "cd"],
        "storage": ["cdn", "assets", "files", "backup", "media", "bucket"],
    }

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

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

    def _normalize_domain(self, value):
        d = str(value).strip().lower()
        d = d.replace("https://", "").replace("http://", "")
        d = d.split("/", 1)[0].strip(".")
        if not d or "." not in d or "@" in d:
            return None
        return d

    def _crtsh_subdomains(self, domain, timeout_seconds):
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp or resp.status_code != 200:
                return []
            rows = resp.json()
            subs = set()
            for row in rows:
                for item in str(row.get("name_value", "")).split("\n"):
                    s = item.strip().lower()
                    if s and "*" not in s and s.endswith(domain):
                        subs.add(s)
            return sorted(subs)
        except Exception:
            return []

    def _map_business_context(self, host):
        h = host.lower()
        contexts = []
        for ctx, words in self.BUSINESS_KEYWORDS.items():
            if any(w in h for w in words):
                contexts.append(ctx)
        return contexts

    def _risk_for_asset(self, contexts, host):
        score = 1
        if "payment" in contexts or "authentication" in contexts:
            score += 4
        if "customer_data" in contexts:
            score += 3
        if "operations" in contexts:
            score += 2
        if "development" in contexts:
            score += 1
        if host.count(".") > 3:
            score += 1
        level = "LOW" if score <= 3 else ("MEDIUM" if score <= 6 else "HIGH")
        return score, level

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid target"}

        timeout_seconds = self._to_int(self.timeout, 8)
        max_subdomains = self._to_int(self.max_subdomains, 80)

        print_info(f"Discovering shadow assets for {domain}")
        subdomains = self._crtsh_subdomains(domain, timeout_seconds)[:max_subdomains]
        findings = []
        for s in subdomains:
            contexts = self._map_business_context(s)
            if not contexts:
                continue
            score, level = self._risk_for_asset(contexts, s)
            findings.append({
                "asset": s,
                "contexts": contexts,
                "business_risk_score": score,
                "business_risk_level": level,
            })

        findings = sorted(findings, key=lambda x: x.get("business_risk_score", 0), reverse=True)
        high = len([f for f in findings if f.get("business_risk_level") == "HIGH"])
        global_level = "LOW"
        if high >= 5:
            global_level = "HIGH"
        elif high >= 1 or len(findings) >= 10:
            global_level = "MEDIUM"

        result = {
            "target": domain,
            "subdomains_discovered": len(subdomains),
            "count": len(findings),
            "high_risk_assets": high,
            "risk_level": global_level,
            "findings": findings[:200],
        }

        print_success(
            f"Shadow assets mapped: {result['count']} contextualized asset(s), "
            f"high_risk={high}, risk={global_level}"
        )

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(result, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")
        return result

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        target = data.get("target", self.target)
        nodes = []
        edges = []
        summary_id = f"shadow_summary_{target}"
        nodes.append({
            "id": summary_id,
            "label": (
                f"Shadow assets ({data.get('risk_level', 'LOW')}) "
                f"- {data.get('count', 0)}"
            ),
            "group": "risk",
            "icon": "📌",
            "custom_info": (
                f"Target: {target}\n"
                f"Discovered subdomains: {data.get('subdomains_discovered', 0)}\n"
                f"Contextualized assets: {data.get('count', 0)}\n"
                f"High risk assets: {data.get('high_risk_assets', 0)}\n"
                f"Global risk: {data.get('risk_level', 'LOW')}"
            ),
        })
        edges.append({
            "from": target,
            "to": summary_id,
            "label": "shadow_summary",
            "custom_info": "Aggregated business risk mapping",
        })
        for i, f in enumerate(data.get("findings", [])[:40]):
            nid = f"shadow_{i}_{target}"
            risk = f.get("business_risk_level", "LOW")
            icon = "🔥" if risk == "HIGH" else ("⚠️" if risk == "MEDIUM" else "🧩")
            label = f"{f.get('asset')} [{','.join(f.get('contexts', []))}]"
            group = "risk" if risk != "LOW" else "hostname"
            nodes.append({
                "id": nid,
                "label": label[:90],
                "group": group,
                "icon": icon,
                "custom_info": (
                    f"Asset: {f.get('asset', 'n/a')}\n"
                    f"Contexts: {', '.join(f.get('contexts', []))}\n"
                    f"Business risk: {f.get('business_risk_level', 'LOW')} ({f.get('business_risk_score', 0)})"
                ),
            })
            edges.append({
                "from": summary_id,
                "to": nid,
                "label": "shadow_asset",
                "custom_info": "Potential shadow IT entrypoint mapped to business context",
            })
        return nodes, edges
