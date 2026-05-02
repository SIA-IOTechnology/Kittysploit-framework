from kittysploit import *
import json
import re
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Azure Blob File Sampler",
        "author": ["KittySploit Team"],
        "description": "Sample high-value blob files by extension/name and rank by likely sensitivity.",
        "tags": ["azure", "cloud", "storage", "triage", "sampling"],
    }

    target = OptString("", "Storage account or blob URL (e.g. opticom)", required=True)
    container = OptString("", "Container name (e.g. media)", required=True)
    sas_token = OptString("", "Optional SAS token without leading '?'", required=False)
    prefix = OptString("", "Optional blob prefix filter", required=False)
    max_files = OptString("0", "Maximum files to inspect (0/all=unlimited)", required=False)
    sample_size = OptString("100", "How many best candidates to keep", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    SENSITIVE_EXT = {
        ".env": 10, ".pem": 10, ".key": 10, ".pfx": 9, ".kdbx": 9,
        ".sql": 8, ".bak": 8, ".dump": 8, ".zip": 6, ".tar": 6, ".gz": 6,
        ".json": 5, ".yml": 5, ".yaml": 5, ".ini": 5, ".cfg": 5,
        ".log": 4, ".txt": 3, ".csv": 3, ".xml": 3,
    }
    NAME_HINTS = {
        "backup": 7, "secret": 9, "token": 8, "credential": 9, "passwd": 9,
        "password": 9, "private": 6, "key": 6, "prod": 5, "internal": 5,
        "db": 5, "dump": 7, "config": 5, "auth": 6,
    }

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

    def _score_file(self, name):
        n = (name or "").lower()
        score = 0
        ext = ""
        dot = n.rfind(".")
        if dot >= 0:
            ext = n[dot:]
        score += self.SENSITIVE_EXT.get(ext, 0)
        for hint, w in self.NAME_HINTS.items():
            if hint in n:
                score += w
        if "/" in n:
            parts = [x for x in n.split("/") if x]
            if len(parts) > 4:
                score += 1
        return score, ext

    def _list_blobs(self, account, container, prefix, sas, timeout_seconds, max_files):
        marker = ""
        files = []
        pages = 0
        while True:
            if max_files > 0:
                remaining = max_files - len(files)
                if remaining <= 0:
                    break
                page_size = min(5000, remaining)
            else:
                page_size = 5000
            q = f"restype=container&comp=list&maxresults={page_size}"
            if prefix:
                q += f"&prefix={prefix}"
            if marker:
                q += f"&marker={marker}"
            if sas:
                q += "&" + sas
            url = f"https://{account}.blob.core.windows.net/{container}?{q}"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp or resp.status_code != 200:
                break
            try:
                root = ET.fromstring(resp.text or "")
            except Exception:
                break
            for blob in root.findall(".//Blob"):
                name = (blob.findtext("Name") or "").strip()
                if name:
                    files.append(name)
            marker = (root.findtext(".//NextMarker") or "").strip()
            pages += 1
            if pages % 2 == 0:
                print_status(f"Sampler progress: pages={pages} files={len(files)}")
            if not marker:
                break
        if max_files > 0:
            return files[:max_files]
        return files

    def run(self):
        account = self._normalize_account(self.target)
        container = str(self.container).strip()
        if not account:
            print_error("target must be a storage account or blob URL")
            return {"error": "invalid target"}
        if not container:
            print_error("container is required")
            return {"error": "container is required"}

        timeout_seconds = self._to_int(self.timeout, 8)
        max_files = self._parse_max(self.max_files)
        sample_size = self._to_int(self.sample_size, 100)
        sas = str(self.sas_token).strip().lstrip("?")
        prefix = str(self.prefix).strip()

        print_info(f"Sampling blob inventory from {account}/{container}")
        files = self._list_blobs(account, container, prefix, sas, timeout_seconds, max_files)
        scored = []
        for name in files:
            s, ext = self._score_file(name)
            if s <= 0:
                continue
            scored.append({"file": name, "score": s, "extension": ext})
        scored = sorted(scored, key=lambda x: x.get("score", 0), reverse=True)[:sample_size]

        risk_score = min(10, max(1, int(sum(x["score"] for x in scored[:20]) / 20))) if scored else 0
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")
        result = {
            "target": f"{account}.blob.core.windows.net/{container}",
            "count_files": len(files),
            "sample_count": len(scored),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "samples": scored,
        }

        print_success(
            f"Sampler done: files={len(files)} candidates={len(scored)} "
            f"risk={risk_level}({risk_score})"
        )
        for s in scored[:25]:
            print_info(f"  [{s['score']}] {s['file']}")

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
        root = data.get("target", "azure-blob-sampler")
        nodes = [{
            "id": root,
            "label": root,
            "group": "hostname",
            "icon": "☁️",
            "custom_info": (
                f"Files: {data.get('count_files', 0)}\n"
                f"Sampled: {data.get('sample_count', 0)}\n"
                f"Risk: {data.get('risk_level', 'LOW')} ({data.get('risk_score', 0)})"
            ),
        }]
        edges = []
        for i, s in enumerate(data.get("samples", [])[:50]):
            nid = f"smp_{i}"
            nodes.append({
                "id": nid,
                "label": f"{s.get('file')} ({s.get('score', 0)})"[:95],
                "group": "risk" if s.get("score", 0) >= 8 else "generic",
                "icon": "🧪",
                "custom_info": f"File: {s.get('file')}\nScore: {s.get('score')}\nExt: {s.get('extension')}",
            })
            edges.append({"from": root, "to": nid, "label": "sample", "custom_info": "High-value candidate"})
        return nodes, edges
