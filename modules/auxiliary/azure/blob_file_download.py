from kittysploit import *
import json
import os
import re
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Azure Blob File Download",
        "author": ["KittySploit Team"],
        "description": "Download selected blob files from Azure container (manual list or flagged scan results).",
        "tags": ["azure", "cloud", "storage", "download"],
    }

    target = OptString("", "Storage account or blob URL (e.g. opticom)", required=True)
    container = OptString("", "Container name (e.g. media)", required=True)
    sas_token = OptString("", "Optional SAS token without leading '?'", required=False)
    files = OptString("", "Comma-separated blob paths to download", required=False)
    findings_file = OptString("", "Optional JSON from blob_sensitive_pattern_scan (uses flagged file list)", required=False)
    auto_collect = OptBool(True, "Auto-list blobs when files/findings are not provided", False)
    prefix = OptString("", "Optional prefix used by auto-list mode", required=False)
    output_dir = OptString("output/azure_blob", "Directory where files are saved", required=False)
    max_files = OptString("50", "Maximum files to download (0/all=unlimited)", required=False)
    max_bytes_per_file = OptString("5000000", "Max bytes accepted per file", required=False)
    timeout = OptString("12", "HTTP timeout in seconds", required=False)
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
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _safe_local_name(self, blob_path):
        clean = str(blob_path).strip().replace("\\", "/")
        clean = clean.lstrip("/")
        clean = re.sub(r"\.\.+", ".", clean)
        clean = re.sub(r"[^a-zA-Z0-9._/\-]", "_", clean)
        if not clean:
            clean = "blob.bin"
        return clean

    def _response_to_bytes(self, resp):
        raw = getattr(resp, "content", None)
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        text = getattr(resp, "text", None)
        if text is None:
            return b""
        # latin-1 preserves byte values 0-255 one-to-one when origin is unknown.
        try:
            return text.encode("latin-1", errors="ignore")
        except Exception:
            return text.encode("utf-8", errors="ignore")

    def _collect_targets(self):
        targets = []
        for item in str(self.files).split(","):
            v = item.strip()
            if v:
                targets.append(v)

        if self.findings_file:
            try:
                with open(str(self.findings_file), "r") as fp:
                    data = json.load(fp)
                for f in data.get("findings", []) or []:
                    name = (f.get("file") or "").strip()
                    if name:
                        targets.append(name)
            except Exception:
                pass

        uniq = []
        seen = set()
        for t in targets:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        return uniq

    def _auto_list_targets(self, account, container, sas, timeout_seconds, max_files, prefix):
        marker = ""
        targets = []
        while True:
            if max_files > 0:
                remaining = max_files - len(targets)
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
                    targets.append(name)
            marker = (root.findtext(".//NextMarker") or "").strip()
            if not marker:
                break
        if max_files > 0:
            return targets[:max_files]
        return targets

    def run(self):
        account = self._normalize_account(self.target)
        container = str(self.container).strip()
        if not account:
            print_error("target must be a storage account or blob URL")
            return {"error": "invalid target"}
        if not container:
            print_error("container is required")
            return {"error": "container is required"}

        timeout_seconds = self._to_int(self.timeout, 12)
        max_bytes = self._to_int(self.max_bytes_per_file, 5000000)
        max_files = self._parse_max(self.max_files)
        sas = str(self.sas_token).strip().lstrip("?")
        prefix = str(self.prefix).strip()
        blob_targets = self._collect_targets()
        if not blob_targets and self.auto_collect:
            print_status("No explicit file list provided, auto-listing blob targets...")
            blob_targets = self._auto_list_targets(account, container, sas, timeout_seconds, max_files, prefix)
            print_info(f"Auto-listed {len(blob_targets)} file target(s)")
        if not blob_targets:
            print_error("No files to download. Set files/findings or enable auto_collect with accessible container.")
            return {"error": "no_files_to_download"}

        out_dir = str(self.output_dir).strip() or "output/azure_blob"
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            print_error(f"Could not create output directory: {e}")
            return {"error": "output_dir_error"}

        print_info(f"Downloading blob files from {account}/{container}")
        downloaded = []
        errors = []

        for i, blob_name in enumerate(blob_targets):
            if max_files > 0 and i >= max_files:
                break
            safe_blob = self._safe_local_name(blob_name)
            q = f"?{sas}" if sas else ""
            url = f"https://{account}.blob.core.windows.net/{container}/{safe_blob}{q}"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                errors.append({"file": blob_name, "error": "request_failed"})
                continue
            if resp.status_code != 200:
                errors.append({"file": blob_name, "error": f"http_{resp.status_code}"})
                continue

            body_bytes = self._response_to_bytes(resp)
            size = len(body_bytes)
            if size > max_bytes:
                errors.append({"file": blob_name, "error": f"too_large_{size}"})
                continue

            local_path = os.path.join(out_dir, safe_blob)
            local_parent = os.path.dirname(local_path)
            try:
                if local_parent:
                    os.makedirs(local_parent, exist_ok=True)
                with open(local_path, "wb") as fp:
                    fp.write(body_bytes)
                downloaded.append({
                    "file": blob_name,
                    "saved_to": local_path,
                    "size": size,
                    "content_type": (resp.headers or {}).get("Content-Type", ""),
                })
                print_success(f"Downloaded: {blob_name} -> {local_path} ({size} bytes)")
            except Exception as e:
                errors.append({"file": blob_name, "error": f"write_failed:{e}"})

        result = {
            "target": f"{account}.blob.core.windows.net/{container}",
            "requested": len(blob_targets),
            "downloaded_count": len(downloaded),
            "error_count": len(errors),
            "downloaded": downloaded,
            "errors": errors,
            "output_dir": out_dir,
        }

        if not downloaded:
            print_warning("No file downloaded.")
        else:
            print_success(f"Download complete: {len(downloaded)} file(s) saved to {out_dir}")
        if errors:
            print_warning(f"Download errors: {len(errors)}")

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
        root = data.get("target", "azure-blob-download")
        nodes = [{
            "id": root,
            "label": root,
            "group": "hostname",
            "icon": "☁️",
            "custom_info": (
                f"Requested: {data.get('requested', 0)}\n"
                f"Downloaded: {data.get('downloaded_count', 0)}\n"
                f"Errors: {data.get('error_count', 0)}\n"
                f"Output dir: {data.get('output_dir', '')}"
            ),
        }]
        edges = []
        for i, f in enumerate(data.get("downloaded", [])[:50]):
            nid = f"dl_{i}"
            nodes.append({
                "id": nid,
                "label": f"{f.get('file')} ({f.get('size', 0)}B)"[:95],
                "group": "generic",
                "icon": "📥",
                "custom_info": (
                    f"File: {f.get('file')}\n"
                    f"Saved to: {f.get('saved_to')}\n"
                    f"Size: {f.get('size', 0)}\n"
                    f"Type: {f.get('content_type', '')}"
                ),
            })
            edges.append({"from": root, "to": nid, "label": "downloaded", "custom_info": "Downloaded blob"})
        return nodes, edges
