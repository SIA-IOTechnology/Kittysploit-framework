from kittysploit import *
import os
import json
from urllib.parse import quote, urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "AWS S3 File Download",
        "author": ["KittySploit Team"],
        "description": "Download a file from an AWS S3 bucket via anonymous access.",
        "tags": ["aws", "s3", "cloud", "download"],
    }

    target = OptString("", "S3 bucket name or URL", required=True)
    key = OptString("", "S3 object key (e.g. backups/db.sql)", required=True)
    output_path = OptString("", "Local output path (default: output/s3_<bucket>_<filename>)", required=False)
    timeout = OptString("20", "HTTP timeout in seconds", required=False)
    overwrite = OptBool(False, "Overwrite output file if it already exists", False)
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
                if host.endswith(".s3.amazonaws.com"):
                    return host.replace(".s3.amazonaws.com", "")
                if host.startswith("s3.") and ".amazonaws.com" in host:
                    path_parts = [p for p in (parsed.path or "").split("/") if p]
                    return path_parts[0] if path_parts else ""
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

    def _default_output_path(self, bucket, key):
        key_name = key.split("/")[-1] or "download.bin"
        safe_bucket = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in bucket)
        return os.path.join("output", f"s3_{safe_bucket}_{key_name}")

    def run(self):
        bucket = self._normalize_bucket(self.target)
        key = str(self.key).strip().lstrip("/")
        if not bucket:
            print_error("target must be an S3 bucket name or URL")
            return {"error": "invalid target"}
        if not key:
            print_error("key is required")
            return {"error": "key is required"}

        timeout_seconds = self._to_int(self.timeout, 20)
        output_path = str(self.output_path).strip() or self._default_output_path(bucket, key)
        if os.path.exists(output_path) and not bool(self.overwrite):
            print_error(f"Output file already exists: {output_path} (set overwrite=true)")
            return {"error": "output exists", "output_path": output_path}

        key_url = quote(key, safe="/")
        url = f"https://{bucket}.s3.amazonaws.com/{key_url}"
        print_info(f"Downloading s3://{bucket}/{key}")
        resp = self._http_get_url(url, timeout_seconds)
        if not resp:
            print_error("Request failed")
            return {"error": "request_failed", "url": url}

        status = resp.status_code
        if status != 200:
            if status in (401, 403):
                print_error("Access denied (object may be private)")
            elif status == 404:
                print_error("Object or bucket not found")
            else:
                print_error(f"Unexpected status code: {status}")
            return {"error": f"http_{status}", "status": status, "url": url}

        body = resp.content if getattr(resp, "content", None) is not None else (resp.text or "").encode()
        size = len(body)
        try:
            out_dir = os.path.dirname(output_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(output_path, "wb") as fp:
                fp.write(body)
            print_success(f"Downloaded {size} bytes to {output_path}")
        except Exception as e:
            print_error(f"Failed to save file: {e}")
            return {"error": "save_failed", "details": str(e), "output_path": output_path}

        result = {
            "provider": "aws_s3",
            "bucket": bucket,
            "key": key,
            "url": url,
            "status": status,
            "size": size,
            "output_path": output_path,
        }

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
        root = data.get("bucket", self.target)
        file_node = f"{root}:{data.get('key', 'object')}"
        nodes = [
            {
                "id": root,
                "label": root,
                "group": "hostname",
                "icon": "🪣",
            },
            {
                "id": file_node,
                "label": data.get("key", "object")[:90],
                "group": "generic",
                "icon": "📥",
                "custom_info": (
                    f"Size: {data.get('size', 0)} bytes\n"
                    f"Saved to: {data.get('output_path', '')}"
                ),
            },
        ]
        edges = [{"from": root, "to": file_node, "label": "downloaded"}]
        return nodes, edges
