from kittysploit import *
import json
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Azure Blob ACL Misconfig Hint",
        "author": ["KittySploit Team"],
        "description": "Analyze blob exposure findings and provide prioritized remediation guidance.",
        "tags": ["azure", "cloud", "storage", "remediation", "misconfiguration"],
    }

    target = OptString("", "Storage account or blob URL (auto mode)", required=False)
    container = OptString("", "Container name for auto mode", required=False)
    sas_token = OptString("", "Optional SAS token without leading '?'", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    auto_collect = OptBool(True, "Auto-collect minimal exposure signal when files are absent", False)
    exposure_file = OptString("", "JSON from blob_exposure_audit", required=False)
    list_file = OptString("", "Optional JSON from blob_container_file_list", required=False)
    sensitive_file = OptString("", "Optional JSON from blob_sensitive_pattern_scan", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_account(self, value):
        raw = str(value).strip()
        if not raw:
            return ""
        if raw.startswith(("http://", "https://")):
            try:
                host = urlparse(raw).hostname or ""
                if host.endswith(".blob.core.windows.net"):
                    return host.split(".")[0]
            except Exception:
                return ""
        return raw.replace(".blob.core.windows.net", "").strip()

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

    def _load_json(self, path):
        if not path:
            return {}
        try:
            with open(str(path), "r") as fp:
                data = json.load(fp)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def run(self):
        exposure = self._load_json(self.exposure_file)
        listing = self._load_json(self.list_file)
        sensitive = self._load_json(self.sensitive_file)
        timeout_seconds = self._to_int(self.timeout, 8)

        if self.auto_collect and not exposure:
            account = self._normalize_account(self.target)
            container = str(self.container).strip()
            sas = str(self.sas_token).strip().lstrip("?")
            if account and container:
                print_info(f"Auto-collecting exposure signal for {account}/{container}")
                q = "restype=container&comp=list&maxresults=1"
                if sas:
                    q += "&" + sas
                url = f"https://{account}.blob.core.windows.net/{container}?{q}"
                resp = self._http_get_url(url, timeout_seconds)
                exposure = {"account": account, "findings": [], "public_listing_count": 0, "public_access_count": 0}
                if resp:
                    b = (resp.text or "").lower()
                    if resp.status_code == 200 and ("<enumerationresults" in b or "<blobs>" in b):
                        exposure["public_listing_count"] = 1
                        exposure["public_access_count"] = 1
                        exposure["findings"].append({"container": container, "exposure": "public_listing", "status_code": 200})
                    elif resp.status_code == 200:
                        exposure["public_access_count"] = 1
                        exposure["findings"].append({"container": container, "exposure": "public_access", "status_code": 200})

        if not exposure:
            print_error("Provide exposure_file or use auto mode with target/container")
            return {"error": "missing_inputs"}

        findings = []
        recommendations = []
        public_listing = [x for x in (exposure.get("findings", []) or []) if x.get("exposure") == "public_listing"]
        public_access = [x for x in (exposure.get("findings", []) or []) if x.get("exposure") == "public_access"]
        flagged = int(sensitive.get("count_flagged", 0) or 0)
        listed_count = int(listing.get("count", 0) or 0)

        if public_listing:
            findings.append({
                "id": "public_listing_enabled",
                "severity": "HIGH",
                "title": "Anonymous blob listing enabled",
                "detail": f"{len(public_listing)} container(s) allow listing.",
            })
            recommendations.append(
                "Set container access level to Private for exposed containers."
            )
            recommendations.append(
                "Disable account-level 'Allow blob public access' unless explicitly required."
            )

        if public_access:
            findings.append({
                "id": "anonymous_read_access",
                "severity": "MEDIUM",
                "title": "Anonymous read access detected",
                "detail": f"{len(public_access)} container(s) appear publicly readable.",
            })
            recommendations.append(
                "Review anonymous read requirement and enforce signed URLs (SAS) for external sharing."
            )

        if listed_count >= 500:
            findings.append({
                "id": "large_public_index",
                "severity": "MEDIUM",
                "title": "Large publicly indexable dataset",
                "detail": f"{listed_count} blobs exposed in listing output.",
            })
            recommendations.append(
                "Segment sensitive blobs into private containers and apply strict naming/lifecycle policies."
            )

        if flagged > 0:
            findings.append({
                "id": "sensitive_patterns_detected",
                "severity": "HIGH",
                "title": "Sensitive patterns found in blob content",
                "detail": f"{flagged} file(s) flagged by sensitive scan.",
            })
            recommendations.append(
                "Rotate exposed credentials/secrets and invalidate tokens immediately."
            )
            recommendations.append(
                "Enable data classification and secret scanning in CI/CD before blob publication."
            )

        if not findings:
            findings.append({
                "id": "no_critical_misconfig_detected",
                "severity": "INFO",
                "title": "No obvious high-impact ACL misconfiguration found",
                "detail": "Still validate IAM roles, SAS scope/expiry, and storage firewall rules.",
            })
            recommendations.append(
                "Keep continuous monitoring for ACL/SAS drift and public exposure regression."
            )

        score = 0
        for f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            if sev == "HIGH":
                score += 3
            elif sev == "MEDIUM":
                score += 2
            elif sev == "LOW":
                score += 1
        score = min(10, score)
        level = "LOW" if score <= 3 else ("MEDIUM" if score <= 6 else "HIGH")

        data = {
            "account": exposure.get("account", ""),
            "risk_score": score,
            "risk_level": level,
            "findings": findings,
            "recommendations": recommendations,
        }

        print_success(f"Misconfig hint generated: {len(findings)} finding(s), risk={level}({score})")
        for f in findings:
            print_warning(f"  [{f.get('severity')}] {f.get('title')}: {f.get('detail')}")
        print_info("Top remediations:")
        for r in recommendations[:8]:
            print_info(f"  - {r}")

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
        root = data.get("account", "azure-account")
        nodes = [{
            "id": root,
            "label": root,
            "group": "risk",
            "icon": "☁️",
            "custom_info": f"Risk: {data.get('risk_level')} ({data.get('risk_score')})",
        }]
        edges = []
        for i, f in enumerate(data.get("findings", [])[:25]):
            nid = f"mis_{i}"
            nodes.append({
                "id": nid,
                "label": f"[{f.get('severity')}] {f.get('title')}"[:95],
                "group": "risk",
                "icon": "⚠️",
                "custom_info": f.get("detail", ""),
            })
            edges.append({"from": root, "to": nid, "label": "finding", "custom_info": f.get("id", "")})
        return nodes, edges
