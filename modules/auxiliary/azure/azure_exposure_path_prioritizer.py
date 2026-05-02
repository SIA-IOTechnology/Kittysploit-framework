from kittysploit import *
import json
import re
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Azure Exposure Path Prioritizer",
        "author": ["KittySploit Team"],
        "description": "Correlate Azure blob findings into prioritized exposure-to-impact paths.",
        "tags": ["azure", "correlation", "attack-path", "prioritization"],
    }

    target = OptString("", "Storage account or blob URL (e.g. opticom)", required=False)
    container = OptString("", "Container name for auto-collection mode (e.g. media)", required=False)
    sas_token = OptString("", "Optional SAS token without leading '?'", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    auto_collect = OptBool(True, "Auto-collect signals from target/container when files are not provided", False)
    max_list_files = OptString("3000", "Maximum files to count during auto-listing (0/all=unlimited)", required=False)
    max_quick_scan_files = OptString("120", "Maximum files to quick-scan during auto mode", required=False)
    max_bytes_per_file = OptString("120000", "Maximum bytes per file in quick sensitive scan", required=False)
    exposure_file = OptString("", "JSON from blob_exposure_audit", required=False)
    list_file = OptString("", "JSON from blob_container_file_list", required=False)
    sensitive_file = OptString("", "JSON from blob_sensitive_pattern_scan", required=False)
    sampler_file = OptString("", "JSON from blob_file_sampler", required=False)
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

    def _auto_collect(self, account, container, sas, timeout_seconds, max_list_files, max_quick_scan_files, max_bytes):
        exposure = {"account": account, "public_listing_count": 0, "public_access_count": 0, "findings": []}
        listing = {"account": account, "count": 0}
        sensitive = {"count_flagged": 0}
        sampler = {"samples": []}

        # Exposure check on selected container.
        q = "restype=container&comp=list&maxresults=1"
        if sas:
            q += "&" + sas
        test_url = f"https://{account}.blob.core.windows.net/{container}?{q}"
        resp = self._http_get_url(test_url, timeout_seconds)
        if resp:
            body = (resp.text or "").lower()
            if resp.status_code == 200 and ("<enumerationresults" in body or "<blobs>" in body):
                exposure["public_listing_count"] = 1
                exposure["public_access_count"] = 1
                exposure["findings"] = [{"container": container, "exposure": "public_listing", "status_code": 200}]
            elif resp.status_code == 200:
                exposure["public_access_count"] = 1
                exposure["findings"] = [{"container": container, "exposure": "public_access", "status_code": 200}]

        # List blobs for count + sampler + quick sensitive scan.
        marker = ""
        names = []
        while True:
            if max_list_files > 0:
                remaining = max_list_files - len(names)
                if remaining <= 0:
                    break
                page_size = min(5000, remaining)
            else:
                page_size = 5000
            q = f"restype=container&comp=list&maxresults={page_size}"
            if marker:
                q += f"&marker={marker}"
            if sas:
                q += "&" + sas
            url = f"https://{account}.blob.core.windows.net/{container}?{q}"
            r = self._http_get_url(url, timeout_seconds)
            if not r or r.status_code != 200:
                break
            try:
                root = ET.fromstring(r.text or "")
            except Exception:
                break
            for blob in root.findall(".//Blob"):
                n = (blob.findtext("Name") or "").strip()
                if n:
                    names.append(n)
            marker = (root.findtext(".//NextMarker") or "").strip()
            if not marker:
                break

        listing["count"] = len(names)

        # Sampler-like high-value scoring.
        hints = ("backup", "secret", "token", "credential", "passwd", "password", "private", "key", "prod", "internal", "db", "dump", "config", "auth")
        ext_weight = {".env": 10, ".pem": 10, ".key": 10, ".pfx": 9, ".sql": 8, ".bak": 8, ".dump": 8, ".zip": 6, ".json": 5, ".yml": 5, ".yaml": 5, ".ini": 5, ".cfg": 5, ".log": 4}
        scored = []
        for n in names:
            low = n.lower()
            score = 0
            dot = low.rfind(".")
            ext = low[dot:] if dot >= 0 else ""
            score += ext_weight.get(ext, 0)
            for h in hints:
                if h in low:
                    score += 4
            if score > 0:
                scored.append({"file": n, "score": score})
        sampler["samples"] = sorted(scored, key=lambda x: x.get("score", 0), reverse=True)[:120]

        # Quick sensitive scan on first files.
        patterns = [
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
            re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[\"'][^\"']{6,}[\"']"),
        ]
        flagged = 0
        for n in names[:max_quick_scan_files]:
            qq = f"?{sas}" if sas else ""
            u = f"https://{account}.blob.core.windows.net/{container}/{n}{qq}"
            rr = self._http_get_url(u, timeout_seconds)
            if not rr or rr.status_code != 200:
                continue
            body = (rr.text or "")[:max_bytes]
            if any(rx.search(body) for rx in patterns):
                flagged += 1
        sensitive["count_flagged"] = flagged
        return exposure, listing, sensitive, sampler

    def _score(self, p):
        return (p.get("impact", 1) * 20) + p.get("confidence", 0) - (p.get("effort", 3) * 10)

    def run(self):
        exposure = self._load_json(self.exposure_file)
        listing = self._load_json(self.list_file)
        sensitive = self._load_json(self.sensitive_file)
        sampler = self._load_json(self.sampler_file)
        top_k = self._to_int(self.top_k, 10)
        timeout_seconds = self._to_int(self.timeout, 8)
        max_list_files = self._parse_max(self.max_list_files)
        max_quick_scan_files = self._to_int(self.max_quick_scan_files, 120)
        max_bytes = self._to_int(self.max_bytes_per_file, 120000)

        # Auto mode: if no JSON inputs, collect directly from target/container.
        if self.auto_collect and not any([exposure, listing, sensitive, sampler]):
            account = self._normalize_account(self.target)
            container = str(self.container).strip()
            sas = str(self.sas_token).strip().lstrip("?")
            if account and container:
                print_info(f"Auto-collecting Azure signals for {account}/{container} ...")
                exposure, listing, sensitive, sampler = self._auto_collect(
                    account,
                    container,
                    sas,
                    timeout_seconds,
                    max_list_files,
                    max_quick_scan_files,
                    max_bytes,
                )
            else:
                print_warning("No input files and no valid target/container for auto mode.")

        account = exposure.get("account") or listing.get("account") or "azure-storage"
        public_listing = int(exposure.get("public_listing_count", 0) or 0)
        public_access = int(exposure.get("public_access_count", 0) or 0)
        file_count = int(listing.get("count", 0) or 0)
        flagged = int(sensitive.get("count_flagged", 0) or 0)
        sampled_high = len([x for x in (sampler.get("samples", []) or []) if int(x.get("score", 0)) >= 8])

        paths = []
        if public_listing > 0:
            paths.append({
                "name": "Public container listing -> bulk data discovery -> data leakage",
                "chain": [account, "public_listing", "blob_inventory", "sensitive_data_exposure"],
                "impact": 4,
                "effort": 1,
                "confidence": min(95, 60 + public_listing * 10 + min(10, file_count // 200)),
                "reason": "Anonymous listing directly exposes object inventory at scale.",
            })
        if flagged > 0:
            paths.append({
                "name": "Public blob read -> sensitive artifact extraction -> credential reuse",
                "chain": [account, "public_read", "sensitive_file", "credential_pivot"],
                "impact": 5,
                "effort": 2,
                "confidence": min(97, 55 + flagged * 6),
                "reason": "Sensitive patterns were detected in downloadable blob content.",
            })
        if sampled_high > 0 and (public_listing > 0 or public_access > 0):
            paths.append({
                "name": "High-value file naming -> targeted download -> operational impact",
                "chain": [account, "high_value_blob_names", "targeted_download", "business_impact"],
                "impact": 4,
                "effort": 2,
                "confidence": min(92, 50 + sampled_high * 4),
                "reason": "Sampler identified high-value file candidates in exposed scope.",
            })
        if not paths:
            paths.append({
                "name": "Recon baseline path",
                "chain": [account, "recon", "manual_validation"],
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
            "account": account,
            "signals": {
                "public_listing_count": public_listing,
                "public_access_count": public_access,
                "listed_files": file_count,
                "flagged_sensitive_files": flagged,
                "high_value_samples": sampled_high,
            },
            "risk_score": risk_score,
            "risk_level": risk_level,
            "count": len(paths),
            "paths": paths,
        }

        print_success(f"Azure exposure paths: {len(paths)} (risk={risk_level}/{risk_score})")
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
        root = data.get("account", "azure-storage")
        nodes = [{
            "id": root,
            "label": f"{root} ({data.get('risk_level', 'LOW')})",
            "group": "risk",
            "icon": "☁️",
            "custom_info": (
                f"Risk: {data.get('risk_level')} ({data.get('risk_score')})\n"
                f"Signals: {json.dumps(data.get('signals', {}), ensure_ascii=True)}"
            ),
        }]
        edges = []
        for i, p in enumerate(data.get("paths", [])[:12]):
            pid = f"az_path_{i}"
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
