from kittysploit import *
import json
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Azure Blob Container File List",
        "author": ["KittySploit Team"],
        "description": "List blobs from an Azure container using anonymous or SAS access.",
        "tags": ["azure", "cloud", "storage", "enumeration"],
    }

    target = OptString("", "Storage account or URL (e.g. opticom or https://opticom.blob.core.windows.net)", required=True)
    container = OptString("", "Container name (e.g. media)", required=True)
    sas_token = OptString("", "Optional SAS token without leading '?'", required=False)
    prefix = OptString("", "Optional blob prefix filter", required=False)
    max_results = OptString("0", "Maximum blobs to return (0 or 'all' = unlimited)", required=False)
    display_mode = OptString("batch", "Display mode: stream|batch|end", required=False)
    display_batch_size = OptString("100", "Batch size for display_mode=batch", required=False)
    progress_every_pages = OptString("1", "Show progress every N pages", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _parse_max_results(self, value):
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

    def _parse_list_xml(self, xml_text):
        blobs = []
        next_marker = ""
        if not xml_text:
            return blobs, next_marker
        try:
            root = ET.fromstring(xml_text)
            for blob in root.findall(".//Blob"):
                name = (blob.findtext("Name") or "").strip()
                props = blob.find("Properties")
                content_type = ""
                last_modified = ""
                size = 0
                if props is not None:
                    content_type = (props.findtext("Content-Type") or "").strip()
                    last_modified = (props.findtext("Last-Modified") or "").strip()
                    try:
                        size = int((props.findtext("Content-Length") or "0").strip())
                    except Exception:
                        size = 0
                if name:
                    blobs.append({
                        "name": name,
                        "size": size,
                        "content_type": content_type,
                        "last_modified": last_modified,
                    })
            next_marker = (root.findtext(".//NextMarker") or "").strip()
        except Exception:
            return [], ""
        return blobs, next_marker

    def run(self):
        account = self._normalize_account(self.target)
        container = str(self.container).strip()
        if not account:
            print_error("target must be a storage account or blob URL")
            return {"error": "invalid target"}
        if not container:
            print_error("container is required")
            return {"error": "container is required"}

        timeout_seconds = self._to_int(self.timeout, 10)
        max_items = self._parse_max_results(self.max_results)
        display_mode = str(self.display_mode).strip().lower() or "batch"
        if display_mode not in ("stream", "batch", "end"):
            display_mode = "batch"
        display_batch_size = self._to_int(self.display_batch_size, 100)
        progress_every_pages = self._to_int(self.progress_every_pages, 1)
        sas = str(self.sas_token).strip().lstrip("?")
        prefix = str(self.prefix).strip()

        print_info(f"Listing blobs from {account}/{container}")
        marker = ""
        collected = []
        access_mode = "anonymous"
        errors = []
        page_count = 0
        displayed_count = 0

        while True:
            if max_items > 0:
                remaining = max_items - len(collected)
                if remaining <= 0:
                    break
                page_size = min(5000, max(1, remaining))
            else:
                page_size = 5000
            query = f"restype=container&comp=list&maxresults={page_size}"
            if prefix:
                query += f"&prefix={prefix}"
            if marker:
                query += f"&marker={marker}"
            if sas:
                query += "&" + sas
                access_mode = "sas"

            url = f"https://{account}.blob.core.windows.net/{container}?{query}"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                errors.append("request_failed")
                break
            if resp.status_code not in (200,):
                errors.append(f"http_{resp.status_code}")
                if resp.status_code in (401, 403):
                    print_error("Access denied. Container might be private or SAS invalid.")
                elif resp.status_code == 404:
                    print_error("Storage account or container not found.")
                else:
                    print_error(f"Unexpected status code: {resp.status_code}")
                break

            blobs, next_marker = self._parse_list_xml(resp.text or "")
            if not blobs and not next_marker:
                break
            collected.extend(blobs)
            page_count += 1

            if progress_every_pages > 0 and page_count % progress_every_pages == 0:
                print_status(
                    f"Listing progress: pages={page_count} discovered={len(collected)} "
                    f"mode={display_mode}"
                )

            if display_mode == "stream":
                for item in blobs:
                    print_info(f"  {item.get('name')} | {item.get('size')} bytes | {item.get('content_type')}")
                    displayed_count += 1
            elif display_mode == "batch":
                while displayed_count + display_batch_size <= len(collected):
                    batch = collected[displayed_count:displayed_count + display_batch_size]
                    print_status(
                        f"Displaying batch {int(displayed_count / max(1, display_batch_size)) + 1} "
                        f"({displayed_count + 1}-{displayed_count + len(batch)})"
                    )
                    for item in batch:
                        print_info(f"  {item.get('name')} | {item.get('size')} bytes | {item.get('content_type')}")
                    displayed_count += len(batch)

            marker = next_marker
            if not marker:
                break

        if max_items > 0:
            collected = collected[:max_items]
        total_bytes = sum(int(x.get("size", 0) or 0) for x in collected)
        result = {
            "target": f"{account}.blob.core.windows.net/{container}",
            "account": account,
            "container": container,
            "access_mode": access_mode,
            "count": len(collected),
            "total_bytes": total_bytes,
            "prefix": prefix,
            "errors": errors,
            "files": collected,
        }

        if collected:
            print_success(f"Found {len(collected)} blob(s), total={total_bytes} bytes")
            if display_mode == "end":
                for item in collected:
                    print_info(f"  {item.get('name')} | {item.get('size')} bytes | {item.get('content_type')}")
            elif display_mode == "batch" and displayed_count < len(collected):
                # Flush remaining partial batch.
                batch = collected[displayed_count:]
                print_status(
                    f"Displaying final batch ({displayed_count + 1}-{displayed_count + len(batch)})"
                )
                for item in batch:
                    print_info(f"  {item.get('name')} | {item.get('size')} bytes | {item.get('content_type')}")
        else:
            print_warning("No blob listed (or inaccessible container).")

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

        root = data.get("target", "azure-blob")
        nodes = [{
            "id": root,
            "label": root,
            "group": "hostname",
            "icon": "☁️",
            "custom_info": (
                f"Container: {data.get('container', 'n/a')}\n"
                f"Mode: {data.get('access_mode', 'unknown')}\n"
                f"Files: {data.get('count', 0)}\n"
                f"Total bytes: {data.get('total_bytes', 0)}"
            ),
        }]
        edges = []
        for i, f in enumerate(data.get("files", [])[:40]):
            nid = f"blob_{i}_{data.get('container', 'c')}"
            label = f"{f.get('name', 'blob')}"
            nodes.append({
                "id": nid,
                "label": label[:90],
                "group": "generic",
                "icon": "📄",
                "custom_info": (
                    f"Name: {f.get('name', 'n/a')}\n"
                    f"Size: {f.get('size', 0)} bytes\n"
                    f"Type: {f.get('content_type', '')}\n"
                    f"Last modified: {f.get('last_modified', '')}"
                ),
            })
            edges.append({
                "from": root,
                "to": nid,
                "label": "blob",
                "custom_info": "Blob object in container",
            })
        return nodes, edges
