from kittysploit import *
import json
import xml.etree.ElementTree as ET
from urllib.parse import quote, urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "GCP GCS Bucket File List",
        "author": ["KittySploit Team"],
        "description": "List files from a Google Cloud Storage bucket using anonymous access.",
        "tags": ["gcp", "gcs", "cloud", "enumeration"],
    }

    target = OptString("", "GCS bucket name or URL (e.g. my-bucket or https://storage.googleapis.com/my-bucket)", required=True)
    prefix = OptString("", "Optional object key prefix", required=False)
    max_results = OptString("0", "Maximum objects to return (0 or 'all' = unlimited)", required=False)
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
        objects = []
        next_token = ""
        if not xml_text:
            return objects, next_token

        def _strip_tag(tag):
            return tag.split("}", 1)[1] if "}" in tag else tag

        try:
            root = ET.fromstring(xml_text)
            for elem in root.iter():
                if _strip_tag(elem.tag) == "Contents":
                    key = ""
                    size = 0
                    last_modified = ""
                    etag = ""
                    storage_class = ""
                    for child in elem:
                        name = _strip_tag(child.tag)
                        value = (child.text or "").strip()
                        if name == "Key":
                            key = value
                        elif name == "Size":
                            try:
                                size = int(value or "0")
                            except Exception:
                                size = 0
                        elif name == "LastModified":
                            last_modified = value
                        elif name == "ETag":
                            etag = value.strip('"')
                        elif name == "StorageClass":
                            storage_class = value
                    if key:
                        objects.append({
                            "key": key,
                            "size": size,
                            "last_modified": last_modified,
                            "etag": etag,
                            "storage_class": storage_class,
                        })

            for elem in root.iter():
                name = _strip_tag(elem.tag)
                if name in ("NextContinuationToken", "NextMarker"):
                    next_token = (elem.text or "").strip()
                    if next_token:
                        break
        except Exception:
            return [], ""
        return objects, next_token

    def run(self):
        bucket = self._normalize_bucket(self.target)
        if not bucket:
            print_error("target must be a GCS bucket name or URL")
            return {"error": "invalid target"}

        timeout_seconds = self._to_int(self.timeout, 10)
        max_items = self._parse_max_results(self.max_results)
        display_mode = str(self.display_mode).strip().lower() or "batch"
        if display_mode not in ("stream", "batch", "end"):
            display_mode = "batch"
        display_batch_size = self._to_int(self.display_batch_size, 100)
        progress_every_pages = self._to_int(self.progress_every_pages, 1)
        prefix = str(self.prefix).strip()

        print_info(f"Listing GCS objects from {bucket}")
        continuation = ""
        collected = []
        errors = []
        page_count = 0
        displayed_count = 0

        while True:
            if max_items > 0:
                remaining = max_items - len(collected)
                if remaining <= 0:
                    break
                page_size = min(1000, max(1, remaining))
            else:
                page_size = 1000

            query = f"list-type=2&max-keys={page_size}"
            if prefix:
                query += f"&prefix={quote(prefix)}"
            if continuation:
                query += f"&continuation-token={quote(continuation)}"

            url = f"https://storage.googleapis.com/{bucket}?{query}"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp:
                errors.append("request_failed")
                break
            if resp.status_code not in (200,):
                errors.append(f"http_{resp.status_code}")
                if resp.status_code in (401, 403):
                    print_error("Access denied. Bucket may be private.")
                elif resp.status_code == 404:
                    print_error("Bucket not found.")
                else:
                    print_error(f"Unexpected status code: {resp.status_code}")
                break

            items, next_token = self._parse_list_xml(resp.text or "")
            if not items and not next_token:
                break
            collected.extend(items)
            page_count += 1

            if progress_every_pages > 0 and page_count % progress_every_pages == 0:
                print_status(
                    f"Listing progress: pages={page_count} discovered={len(collected)} "
                    f"mode={display_mode}"
                )

            if display_mode == "stream":
                for item in items:
                    print_info(f"  {item.get('key')} | {item.get('size')} bytes | {item.get('storage_class')}")
                    displayed_count += 1
            elif display_mode == "batch":
                while displayed_count + display_batch_size <= len(collected):
                    batch = collected[displayed_count:displayed_count + display_batch_size]
                    print_status(
                        f"Displaying batch {int(displayed_count / max(1, display_batch_size)) + 1} "
                        f"({displayed_count + 1}-{displayed_count + len(batch)})"
                    )
                    for item in batch:
                        print_info(f"  {item.get('key')} | {item.get('size')} bytes | {item.get('storage_class')}")
                    displayed_count += len(batch)

            continuation = next_token
            if not continuation:
                break

        if max_items > 0:
            collected = collected[:max_items]
        total_bytes = sum(int(x.get("size", 0) or 0) for x in collected)
        result = {
            "target": f"storage.googleapis.com/{bucket}",
            "provider": "gcp_gcs",
            "bucket": bucket,
            "count": len(collected),
            "total_bytes": total_bytes,
            "prefix": prefix,
            "errors": errors,
            "files": collected,
        }

        if collected:
            print_success(f"Found {len(collected)} object(s), total={total_bytes} bytes")
            if display_mode == "end":
                for item in collected:
                    print_info(f"  {item.get('key')} | {item.get('size')} bytes | {item.get('storage_class')}")
            elif display_mode == "batch" and displayed_count < len(collected):
                batch = collected[displayed_count:]
                print_status(
                    f"Displaying final batch ({displayed_count + 1}-{displayed_count + len(batch)})"
                )
                for item in batch:
                    print_info(f"  {item.get('key')} | {item.get('size')} bytes | {item.get('storage_class')}")
        else:
            print_warning("No object listed (or inaccessible bucket).")

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

        root = data.get("target", "gcs")
        nodes = [{
            "id": root,
            "label": root,
            "group": "hostname",
            "icon": "🟥",
            "custom_info": (
                f"Bucket: {data.get('bucket', 'n/a')}\n"
                f"Files: {data.get('count', 0)}\n"
                f"Total bytes: {data.get('total_bytes', 0)}"
            ),
        }]
        edges = []
        for i, f in enumerate(data.get("files", [])[:40]):
            nid = f"gcs_{i}_{data.get('bucket', 'b')}"
            nodes.append({
                "id": nid,
                "label": f.get("key", "object")[:90],
                "group": "generic",
                "icon": "📄",
                "custom_info": (
                    f"Key: {f.get('key', 'n/a')}\n"
                    f"Size: {f.get('size', 0)} bytes\n"
                    f"Storage class: {f.get('storage_class', '')}\n"
                    f"Last modified: {f.get('last_modified', '')}"
                ),
            })
            edges.append({
                "from": root,
                "to": nid,
                "label": "object",
                "custom_info": "GCS object in bucket",
            })
        return nodes, edges
