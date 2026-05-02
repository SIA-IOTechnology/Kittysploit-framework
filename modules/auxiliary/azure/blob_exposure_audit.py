from kittysploit import *
import json
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Azure Blob Exposure Audit",
        "author": ["KittySploit Team"],
        "description": "Audit multiple Azure blob containers for anonymous exposure and listing.",
        "tags": ["azure", "cloud", "storage", "audit"],
    }

    target = OptString("", "Storage account or blob URL (e.g. opticom)", required=True)
    container = OptString("", "Single container name (optional, prioritized when set)", required=False)
    containers = OptString("media,assets,public,backup,files,uploads,logs,data", "Comma-separated container names", required=False)
    sas_token = OptString("", "Optional SAS token without leading '?'", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
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

    def _container_candidates(self):
        cands = []
        single = str(self.container).strip().lower()
        if single:
            cands.append(single)
        for c in str(self.containers).split(","):
            cc = c.strip().lower()
            if cc and cc not in cands:
                cands.append(cc)
        return cands

    def _classify(self, status_code, body):
        b = (body or "").lower()
        if status_code == 200 and ("<enumerationresults" in b or "<blobs>" in b):
            return "public_listing", 95
        if status_code == 200:
            return "public_access", 70
        if status_code in (401, 403):
            return "restricted_or_private", 20
        if status_code == 404:
            return "not_found", 0
        return "unknown", 10

    def run(self):
        account = self._normalize_account(self.target)
        if not account:
            print_error("target must be a storage account or blob URL")
            return {"error": "invalid target"}

        timeout_seconds = self._to_int(self.timeout, 8)
        sas = str(self.sas_token).strip().lstrip("?")
        cands = self._container_candidates()
        if not cands:
            print_error("No container candidates provided")
            return {"error": "no containers"}

        print_info(f"Auditing blob exposure on account: {account}")
        findings = []
        for c in cands:
            query = "restype=container&comp=list&maxresults=1"
            if sas:
                query += "&" + sas
            url = f"https://{account}.blob.core.windows.net/{c}?{query}"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                findings.append({
                    "container": c,
                    "status_code": None,
                    "exposure": "request_failed",
                    "confidence": 0,
                })
                continue
            exposure, conf = self._classify(resp.status_code, resp.text or "")
            findings.append({
                "container": c,
                "status_code": resp.status_code,
                "exposure": exposure,
                "confidence": conf,
                "url": resp.url or url,
            })

        public_listing = [f for f in findings if f.get("exposure") == "public_listing"]
        public_any = [f for f in findings if f.get("exposure") in ("public_listing", "public_access")]
        risk_score = min(10, (len(public_listing) * 3) + (len(public_any) - len(public_listing)))
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")
        result = {
            "account": account,
            "count": len(findings),
            "public_listing_count": len(public_listing),
            "public_access_count": len(public_any),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings,
        }

        print_success(
            f"Exposure audit done: tested={len(findings)} "
            f"public_listing={len(public_listing)} risk={risk_level}({risk_score})"
        )
        for f in findings:
            if f.get("exposure") in ("public_listing", "public_access"):
                print_warning(
                    f"  [{f.get('container')}] {f.get('exposure')} "
                    f"(http={f.get('status_code')}, confidence={f.get('confidence')})"
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
        account = data.get("account", self.target)
        root = f"{account}.blob.core.windows.net"
        nodes = [{
            "id": root,
            "label": root,
            "group": "hostname",
            "icon": "☁️",
            "custom_info": (
                f"Risk: {data.get('risk_level', 'LOW')} ({data.get('risk_score', 0)})\n"
                f"Public listing: {data.get('public_listing_count', 0)}\n"
                f"Public access: {data.get('public_access_count', 0)}"
            ),
        }]
        edges = []
        for i, f in enumerate(data.get("findings", [])[:60]):
            nid = f"container_{i}_{account}"
            exposure = f.get("exposure", "unknown")
            icon = "🔥" if exposure == "public_listing" else ("⚠️" if exposure == "public_access" else "📦")
            group = "risk" if exposure in ("public_listing", "public_access") else "generic"
            nodes.append({
                "id": nid,
                "label": f"{f.get('container')} ({exposure})",
                "group": group,
                "icon": icon,
                "custom_info": (
                    f"Container: {f.get('container')}\n"
                    f"Exposure: {exposure}\n"
                    f"HTTP: {f.get('status_code')}\n"
                    f"Confidence: {f.get('confidence', 0)}"
                ),
            })
            edges.append({"from": root, "to": nid, "label": "container", "custom_info": exposure})
        return nodes, edges
