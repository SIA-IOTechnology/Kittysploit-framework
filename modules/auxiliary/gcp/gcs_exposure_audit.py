from kittysploit import *
import json
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "GCP GCS Exposure Audit",
        "author": ["KittySploit Team"],
        "description": "Audit multiple GCS buckets for anonymous listing/public exposure indicators.",
        "tags": ["gcp", "gcs", "cloud", "audit", "misconfig"],
    }

    target = OptString("", "Single bucket name or URL (optional, prioritized when set)", required=False)
    buckets = OptString("assets,media,public,backup,files,uploads,logs,data", "Comma-separated bucket candidates", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_bucket(self, value):
        raw = str(value).strip()
        if not raw:
            return ""
        if raw.startswith(("http://", "https://")):
            try:
                parsed = urlparse(raw)
                host = parsed.hostname or ""
                if host == "storage.googleapis.com":
                    path_parts = [p for p in (parsed.path or "").split("/") if p]
                    return path_parts[0] if path_parts else ""
                if host.endswith(".storage.googleapis.com"):
                    return host.replace(".storage.googleapis.com", "")
                return host.split(".")[0]
            except Exception:
                return ""
        return raw

    def _bucket_candidates(self):
        cands = []
        single = self._normalize_bucket(self.target)
        if single:
            cands.append(single)
        for b in str(self.buckets).split(","):
            bb = self._normalize_bucket(b)
            if bb and bb not in cands:
                cands.append(bb)
        return cands

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

    def _classify(self, status_code, body):
        b = (body or "").lower()
        if status_code == 200 and ("listbucketresult" in b or "<contents>" in b):
            return "public_listing", 95
        if status_code == 200:
            return "public_access", 70
        if status_code in (401, 403):
            return "restricted_or_private", 20
        if status_code == 404 and ("nosuchbucket" in b or "not found" in b):
            return "not_found", 0
        return "unknown", 10

    def run(self):
        timeout_seconds = self._to_int(self.timeout, 8)
        candidates = self._bucket_candidates()
        if not candidates:
            print_error("No bucket candidates provided")
            return {"error": "no buckets"}

        print_info(f"Auditing GCS exposure over {len(candidates)} candidate bucket(s)")
        findings = []
        for bucket in candidates:
            url = f"https://storage.googleapis.com/{bucket}?list-type=2&max-keys=1"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                findings.append({
                    "bucket": bucket,
                    "status_code": None,
                    "exposure": "request_failed",
                    "confidence": 0,
                })
                continue
            exposure, confidence = self._classify(resp.status_code, resp.text or "")
            findings.append({
                "bucket": bucket,
                "status_code": resp.status_code,
                "exposure": exposure,
                "confidence": confidence,
                "url": resp.url or url,
            })

        public_listing = [f for f in findings if f.get("exposure") == "public_listing"]
        public_any = [f for f in findings if f.get("exposure") in ("public_listing", "public_access")]
        risk_score = min(10, (len(public_listing) * 3) + (len(public_any) - len(public_listing)))
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")
        result = {
            "provider": "gcp_gcs",
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
                    f"  [{f.get('bucket')}] {f.get('exposure')} "
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
        root = "gcs-audit"
        nodes = [{
            "id": root,
            "label": root,
            "group": "hostname",
            "icon": "🟥",
            "custom_info": (
                f"Risk: {data.get('risk_level', 'LOW')} ({data.get('risk_score', 0)})\n"
                f"Public listing: {data.get('public_listing_count', 0)}\n"
                f"Public access: {data.get('public_access_count', 0)}"
            ),
        }]
        edges = []
        for i, f in enumerate(data.get("findings", [])[:60]):
            nid = f"gcs_bucket_{i}"
            exposure = f.get("exposure", "unknown")
            icon = "🔥" if exposure == "public_listing" else ("⚠️" if exposure == "public_access" else "🪣")
            group = "risk" if exposure in ("public_listing", "public_access") else "generic"
            nodes.append({
                "id": nid,
                "label": f"{f.get('bucket')} ({exposure})",
                "group": group,
                "icon": icon,
                "custom_info": (
                    f"Bucket: {f.get('bucket')}\n"
                    f"Exposure: {exposure}\n"
                    f"HTTP: {f.get('status_code')}\n"
                    f"Confidence: {f.get('confidence', 0)}"
                ),
            })
            edges.append({"from": root, "to": nid, "label": "bucket", "custom_info": exposure})
        return nodes, edges
