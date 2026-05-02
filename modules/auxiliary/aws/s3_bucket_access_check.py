from kittysploit import *
import json
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "AWS S3 Bucket Access Check",
        "author": ["KittySploit Team"],
        "description": "Check anonymous read/list exposure indicators on an AWS S3 bucket.",
        "tags": ["aws", "s3", "cloud", "misconfig", "exposure"],
    }

    target = OptString("", "S3 bucket name or URL", required=True)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
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

    def _contains_any(self, text, needles):
        data = (text or "").lower()
        return any(n in data for n in needles)

    def run(self):
        bucket = self._normalize_bucket(self.target)
        if not bucket:
            print_error("target must be an S3 bucket name or URL")
            return {"error": "invalid target"}

        timeout_seconds = self._to_int(self.timeout, 10)
        checks = []

        # Check anonymous listing via S3 API endpoint.
        list_url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=5"
        list_resp = self._http_get_url(list_url, timeout_seconds)
        list_status = list_resp.status_code if list_resp else None
        list_body = (list_resp.text or "")[:8000].lower() if list_resp else ""
        list_public = bool(
            list_resp
            and list_status == 200
            and self._contains_any(list_body, ["listbucketresult", "<contents>"])
        )
        checks.append({
            "name": "anonymous_list_objects",
            "url": list_url,
            "status": list_status,
            "success": list_public,
            "signal": "bucket_listing_enabled" if list_public else "listing_not_public",
        })

        # Check website endpoint reachability (can reveal object hosting).
        website_url = f"http://{bucket}.s3-website-us-east-1.amazonaws.com/"
        website_resp = self._http_get_url(website_url, timeout_seconds)
        website_status = website_resp.status_code if website_resp else None
        website_body = (website_resp.text or "")[:4000].lower() if website_resp else ""
        website_enabled = bool(
            website_resp
            and website_status in (200, 301, 302, 403, 404)
            and not self._contains_any(website_body, ["nosuchbucket"])
        )
        checks.append({
            "name": "website_endpoint_enabled",
            "url": website_url,
            "status": website_status,
            "success": website_enabled,
            "signal": "website_endpoint_detected" if website_enabled else "website_endpoint_not_detected",
        })

        # Probe for explicit deny/not-found hints.
        bucket_exists_hint = False
        if list_resp:
            if list_status in (200, 403):
                bucket_exists_hint = True
            if self._contains_any(list_body, ["accessdenied", "all access to this object"]):
                bucket_exists_hint = True

        risk_level = "LOW"
        if list_public:
            risk_level = "HIGH"
        elif website_enabled:
            risk_level = "MEDIUM"

        result = {
            "provider": "aws_s3",
            "target": bucket,
            "bucket": bucket,
            "bucket_exists_hint": bucket_exists_hint,
            "anonymous_list_public": list_public,
            "website_endpoint_enabled": website_enabled,
            "risk_level": risk_level,
            "checks": checks,
        }

        if list_public:
            print_warning(f"Bucket {bucket} appears publicly listable (anonymous ListBucket)")
        elif bucket_exists_hint:
            print_info(f"Bucket {bucket} appears to exist but listing is restricted")
        else:
            print_success(f"No public listing signal detected for {bucket}")

        if website_enabled:
            print_status("S3 website endpoint appears enabled/reachable")

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
        risk = data.get("risk_level", "LOW")
        root_icon = "🔓" if data.get("anonymous_list_public") else "🪣"
        nodes = [{
            "id": root,
            "label": f"{root} ({risk})",
            "group": "hostname",
            "icon": root_icon,
            "custom_info": (
                f"Provider: aws_s3\n"
                f"Anonymous list: {data.get('anonymous_list_public', False)}\n"
                f"Website endpoint: {data.get('website_endpoint_enabled', False)}\n"
                f"Bucket exists hint: {data.get('bucket_exists_hint', False)}"
            ),
        }]
        edges = []
        for i, chk in enumerate(data.get("checks", [])):
            nid = f"check_{i}_{root}"
            icon = "✅" if chk.get("success") else "❌"
            nodes.append({
                "id": nid,
                "label": chk.get("name", "check"),
                "group": "generic",
                "icon": icon,
                "custom_info": (
                    f"URL: {chk.get('url', '')}\n"
                    f"Status: {chk.get('status', 'n/a')}\n"
                    f"Signal: {chk.get('signal', '')}"
                ),
            })
            edges.append({
                "from": root,
                "to": nid,
                "label": "check",
                "custom_info": "S3 exposure check",
            })
        return nodes, edges
