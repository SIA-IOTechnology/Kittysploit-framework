from kittysploit import *
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import quote, urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "GCP GCS Exposure Path Prioritizer",
        "author": ["KittySploit Team"],
        "description": "Correlate GCS findings into prioritized exposure-to-impact paths.",
        "tags": ["gcp", "gcs", "correlation", "attack-path", "prioritization"],
    }

    target = OptString("", "GCS bucket name or URL (for auto-collection mode)", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    auto_collect = OptBool(True, "Auto-collect signals from target when files are not provided", False)
    max_list_files = OptString("3000", "Maximum files to count during auto-listing (0/all=unlimited)", required=False)
    max_quick_scan_files = OptString("120", "Maximum files to quick-scan during auto mode", required=False)
    max_bytes_per_file = OptString("120000", "Maximum bytes per file in quick sensitive scan", required=False)
    exposure_file = OptString("", "JSON from gcs_exposure_audit", required=False)
    list_file = OptString("", "JSON from gcs_bucket_file_list", required=False)
    sensitive_file = OptString("", "JSON from gcs_sensitive_pattern_scan", required=False)
    top_k = OptString("10", "Maximum prioritized paths", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _parse_max(self, value):
        raw = str(value).strip().lower()
        if raw in ("0", "all", "unlimited", "none", ""):
            return 0
        try:
            return max(1, int(raw))
        except Exception:
            return 0

    def _load_json(self, path):
        if not path:
            return {}
        try:
            with open(str(path), "r") as fp:
                data = json.load(fp)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

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

    def _list_object_names(self, bucket, timeout_seconds, max_list_files):
        token = ""
        names = []

        def _strip_tag(tag):
            return tag.split("}", 1)[1] if "}" in tag else tag

        while True:
            if max_list_files > 0:
                remaining = max_list_files - len(names)
                if remaining <= 0:
                    break
                page_size = min(1000, remaining)
            else:
                page_size = 1000

            query = f"list-type=2&max-keys={page_size}"
            if token:
                query += f"&continuation-token={quote(token)}"
            url = f"https://storage.googleapis.com/{bucket}?{query}"
            r = self._http_get_url(url, timeout_seconds)
            if not r or r.status_code != 200:
                break
            try:
                root = ET.fromstring(r.text or "")
            except Exception:
                break

            for elem in root.iter():
                if _strip_tag(elem.tag) == "Contents":
                    key = ""
                    for child in elem:
                        if _strip_tag(child.tag) == "Key":
                            key = (child.text or "").strip()
                            break
                    if key:
                        names.append(key)

            token = ""
            for elem in root.iter():
                if _strip_tag(elem.tag) in ("NextContinuationToken", "NextMarker"):
                    token = (elem.text or "").strip()
                    if token:
                        break
            if not token:
                break
        return names

    def _auto_collect(self, bucket, timeout_seconds, max_list_files, max_quick_scan_files, max_bytes):
        exposure = {
            "public_listing_count": 0,
            "public_access_count": 0,
            "findings": [],
        }
        listing = {"bucket": bucket, "count": 0}
        sensitive = {"count_flagged": 0}

        test_url = f"https://storage.googleapis.com/{bucket}?list-type=2&max-keys=1"
        resp = self._http_get_url(test_url, timeout_seconds)
        if resp:
            body = (resp.text or "").lower()
            if resp.status_code == 200 and ("listbucketresult" in body or "<contents>" in body):
                exposure["public_listing_count"] = 1
                exposure["public_access_count"] = 1
                exposure["findings"] = [{"bucket": bucket, "exposure": "public_listing", "status_code": 200}]
            elif resp.status_code == 200:
                exposure["public_access_count"] = 1
                exposure["findings"] = [{"bucket": bucket, "exposure": "public_access", "status_code": 200}]

        names = self._list_object_names(bucket, timeout_seconds, max_list_files)
        listing["count"] = len(names)

        patterns = [
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
            re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[\"'][^\"']{6,}[\"']"),
        ]
        flagged = 0
        for n in names[:max_quick_scan_files]:
            u = f"https://storage.googleapis.com/{bucket}/{quote(n, safe='/')}"
            rr = self._http_get_url(u, timeout_seconds)
            if not rr or rr.status_code != 200:
                continue
            body = (rr.text or "")[:max_bytes]
            if any(rx.search(body) for rx in patterns):
                flagged += 1
        sensitive["count_flagged"] = flagged
        return exposure, listing, sensitive

    def _score(self, path_data):
        return (path_data.get("impact", 1) * 20) + path_data.get("confidence", 0) - (path_data.get("effort", 3) * 10)

    def run(self):
        exposure = self._load_json(self.exposure_file)
        listing = self._load_json(self.list_file)
        sensitive = self._load_json(self.sensitive_file)
        top_k = self._to_int(self.top_k, 10)
        timeout_seconds = self._to_int(self.timeout, 8)
        max_list_files = self._parse_max(self.max_list_files)
        max_quick_scan_files = self._to_int(self.max_quick_scan_files, 120)
        max_bytes = self._to_int(self.max_bytes_per_file, 120000)

        if self.auto_collect and not any([exposure, listing, sensitive]):
            bucket = self._normalize_bucket(self.target)
            if bucket:
                print_info(f"Auto-collecting GCS signals for {bucket} ...")
                exposure, listing, sensitive = self._auto_collect(
                    bucket,
                    timeout_seconds,
                    max_list_files,
                    max_quick_scan_files,
                    max_bytes,
                )
            else:
                print_warning("No input files and no valid target for auto mode.")

        bucket = self._normalize_bucket(listing.get("bucket") or self.target) or "gcs-bucket"
        public_listing = int(exposure.get("public_listing_count", 0) or 0)
        public_access = int(exposure.get("public_access_count", 0) or 0)
        file_count = int(listing.get("count", 0) or 0)
        flagged = int(sensitive.get("count_flagged", 0) or 0)

        paths = []
        if public_listing > 0:
            paths.append({
                "name": "Public bucket listing -> bulk object discovery -> data leakage",
                "chain": [bucket, "public_listing", "object_inventory", "sensitive_data_exposure"],
                "impact": 4,
                "effort": 1,
                "confidence": min(95, 60 + public_listing * 10 + min(10, file_count // 200)),
                "reason": "Anonymous listing exposes GCS object inventory at scale.",
            })
        if flagged > 0:
            paths.append({
                "name": "Public object read -> secret extraction -> credential pivot",
                "chain": [bucket, "public_read", "sensitive_object", "credential_reuse"],
                "impact": 5,
                "effort": 2,
                "confidence": min(97, 55 + flagged * 6),
                "reason": "Sensitive patterns were detected in downloadable GCS objects.",
            })
        if public_access > 0 and file_count > 0:
            paths.append({
                "name": "Public read exposure -> targeted file theft -> business impact",
                "chain": [bucket, "public_read", "targeted_download", "business_impact"],
                "impact": 4,
                "effort": 2,
                "confidence": min(92, 50 + min(20, file_count // 100)),
                "reason": "Public read signal plus non-empty inventory indicates practical data exfiltration path.",
            })
        if not paths:
            paths.append({
                "name": "Recon baseline path",
                "chain": [bucket, "recon", "manual_validation"],
                "impact": 2,
                "effort": 3,
                "confidence": 35,
                "reason": "Insufficient correlation signals for stronger automated chain.",
            })

        for p in paths:
            p["priority_score"] = self._score(p)
        paths = sorted(paths, key=lambda x: x["priority_score"], reverse=True)[:top_k]

        risk_score = min(10, max(1, int(sum(max(0, p["priority_score"]) for p in paths) / 80)))
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")
        result = {
            "provider": "gcp_gcs",
            "bucket": bucket,
            "signals": {
                "public_listing_count": public_listing,
                "public_access_count": public_access,
                "listed_files": file_count,
                "flagged_sensitive_files": flagged,
            },
            "risk_score": risk_score,
            "risk_level": risk_level,
            "count": len(paths),
            "paths": paths,
        }

        print_success(f"GCS exposure paths: {len(paths)} (risk={risk_level}/{risk_score})")
        for i, p in enumerate(paths[:10], 1):
            print_info(
                f"  {i}. {p['name']} | score={p['priority_score']} "
                f"| impact={p['impact']} effort={p['effort']} conf={p['confidence']}"
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
        root = data.get("bucket", "gcs-bucket")
        nodes = [{
            "id": root,
            "label": f"{root} ({data.get('risk_level', 'LOW')})",
            "group": "risk",
            "icon": "🟥",
            "custom_info": (
                f"Risk: {data.get('risk_level')} ({data.get('risk_score')})\n"
                f"Signals: {json.dumps(data.get('signals', {}), ensure_ascii=True)}"
            ),
        }]
        edges = []
        for i, p in enumerate(data.get("paths", [])[:12]):
            pid = f"gcs_path_{i}"
            nodes.append({
                "id": pid,
                "label": f"{p.get('name')} ({p.get('priority_score', 0)})"[:95],
                "group": "risk",
                "icon": "🧭",
                "custom_info": (
                    f"Reason: {p.get('reason')}\n"
                    f"Impact: {p.get('impact')}\nEffort: {p.get('effort')}\nConfidence: {p.get('confidence')}"
                ),
            })
            edges.append({"from": root, "to": pid, "label": "path", "custom_info": p.get("reason", "")})
        return nodes, edges
