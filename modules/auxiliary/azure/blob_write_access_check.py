from kittysploit import *
import json
import time
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Azure Blob Write Access Check",
        "author": ["KittySploit Team"],
        "description": "Check whether blob upload is possible (dry-run by default, controlled write test optional).",
        "tags": ["azure", "cloud", "storage", "access-check", "write"],
    }

    target = OptString("", "Storage account or blob URL (e.g. opticom)", required=True)
    container = OptString("", "Container name (e.g. media)", required=True)
    sas_token = OptString("", "Optional SAS token without leading '?'", required=False)
    dry_run = OptBool(True, "Do not perform upload; only infer from token/response context", False)
    test_blob_name = OptString("", "Optional test blob name (default: ks-write-check-<ts>.txt)", required=False)
    cleanup = OptBool(True, "Delete temporary test blob when upload succeeds", False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
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

    def _parse_sas_permissions(self, sas_token):
        perms = ""
        for part in str(sas_token).split("&"):
            if part.startswith("sp="):
                perms = part.split("=", 1)[1]
                break
        return perms

    def _http_request_url(self, method, url, timeout_seconds, headers=None, data=""):
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
                method=method,
                path=path,
                timeout=timeout_seconds,
                headers=headers or {},
                data=data,
                allow_redirects=True,
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _build_blob_url(self, account, container, blob_name, sas):
        q = f"?{sas}" if sas else ""
        return f"https://{account}.blob.core.windows.net/{container}/{blob_name}{q}"

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
        sas = str(self.sas_token).strip().lstrip("?")
        dry_run = bool(self.dry_run)
        blob_name = str(self.test_blob_name).strip() or f"ks-write-check-{int(time.time())}.txt"

        permissions = self._parse_sas_permissions(sas) if sas else ""
        inferred_write = ("w" in permissions or "c" in permissions or "a" in permissions)
        notes = []
        if sas:
            notes.append(f"SAS permissions: {permissions or 'unknown'}")
        else:
            notes.append("No SAS token provided; anonymous write is usually denied on Azure Blob.")

        target_blob_url = self._build_blob_url(account, container, blob_name, sas)
        result = {
            "target": f"{account}.blob.core.windows.net/{container}",
            "blob_test_name": blob_name,
            "mode": "dry_run" if dry_run else "controlled_write_test",
            "sas_permissions": permissions,
            "inferred_write_possible": inferred_write,
            "write_check": "not_tested",
            "cleanup_status": "not_applicable",
            "http_status": None,
            "notes": notes,
        }

        if dry_run:
            print_info(f"Dry-run mode: write inference for {account}/{container}")
            if inferred_write:
                print_warning("SAS token appears to include write/create permission (w/c/a).")
                result["write_check"] = "likely_possible"
            else:
                print_status("No write permission inferred from available context.")
                result["write_check"] = "unlikely_without_credentials"
        else:
            print_info(f"Controlled write test to {account}/{container} with blob {blob_name}")
            body = "Kittysploit Azure write-check test file.\n"
            headers = {
                "x-ms-blob-type": "BlockBlob",
                "x-ms-version": "2021-10-04",
                "Content-Type": "text/plain",
                "If-None-Match": "*",
            }
            put_resp = self._http_request_url(
                method="PUT",
                url=target_blob_url,
                timeout_seconds=timeout_seconds,
                headers=headers,
                data=body,
            )
            if not put_resp:
                result["write_check"] = "request_failed"
                notes.append("PUT request failed before HTTP response.")
                print_error("Write test failed: request failed")
            else:
                result["http_status"] = put_resp.status_code
                if put_resp.status_code in (200, 201):
                    result["write_check"] = "write_confirmed"
                    print_success(f"Write confirmed (HTTP {put_resp.status_code})")
                    if self.cleanup:
                        del_headers = {"x-ms-version": "2021-10-04"}
                        del_resp = self._http_request_url(
                            method="DELETE",
                            url=target_blob_url,
                            timeout_seconds=timeout_seconds,
                            headers=del_headers,
                            data="",
                        )
                        if del_resp and del_resp.status_code in (202, 204):
                            result["cleanup_status"] = "deleted"
                            print_success("Temporary test blob deleted")
                        else:
                            result["cleanup_status"] = "delete_failed"
                            print_warning("Temporary test blob could not be deleted")
                elif put_resp.status_code in (401, 403):
                    result["write_check"] = "denied"
                    print_status("Write denied (expected for anonymous/public-read containers)")
                elif put_resp.status_code == 404:
                    result["write_check"] = "container_or_account_not_found"
                    print_error("Container/account not found")
                elif put_resp.status_code == 412:
                    result["write_check"] = "blob_already_exists"
                    print_warning("Test blob already exists (precondition failed)")
                else:
                    result["write_check"] = f"unexpected_http_{put_resp.status_code}"
                    print_warning(f"Unexpected write response: HTTP {put_resp.status_code}")

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
        root = data.get("target", "azure-blob-write-check")
        check = data.get("write_check", "unknown")
        risk_group = "risk" if check in ("write_confirmed", "likely_possible") else "generic"
        nodes = [{
            "id": root,
            "label": root,
            "group": "hostname",
            "icon": "☁️",
            "custom_info": (
                f"Mode: {data.get('mode', '')}\n"
                f"Write check: {check}\n"
                f"HTTP: {data.get('http_status')}\n"
                f"Cleanup: {data.get('cleanup_status')}"
            ),
        }, {
            "id": f"{root}_result",
            "label": f"write_check: {check}",
            "group": risk_group,
            "icon": "✍️",
            "custom_info": "\n".join(data.get("notes", [])[:8]),
        }]
        edges = [{
            "from": root,
            "to": f"{root}_result",
            "label": "write_access",
            "custom_info": "Azure blob write capability check",
        }]
        return nodes, edges
