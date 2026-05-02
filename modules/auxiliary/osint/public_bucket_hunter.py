from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Public Bucket Hunter",
        "author": ["KittySploit Team"],
        "description": "Hunt likely public cloud storage buckets (S3/GCS/Azure Blob) from domain naming patterns.",
        "tags": ["osint", "passive", "cloud", "bucket"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    max_candidates = OptString("80", "Maximum bucket candidates to test", required=False)
    include_restricted = OptBool(False, "Include restricted-but-existing buckets in findings", False)
    output_file = OptString("", "Optional JSON output file", required=False)

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

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _build_candidates(self, domain):
        base = domain.lower().strip()
        naked = base.replace(".", "-")
        root = base.split(".")[0]
        words = [root, naked, base]
        suffixes = ["assets", "static", "cdn", "media", "files", "backup", "uploads", "public"]
        cands = set(words)
        for w in words:
            for s in suffixes:
                cands.add(f"{w}-{s}")
                cands.add(f"{s}-{w}")
                cands.add(f"{w}.{s}")
        return sorted(cands)

    def _probe(self, url, timeout_seconds):
        try:
            r = self._http_get_url(url, timeout_seconds)
            if not r:
                return None, url, ""
            body = (r.text or "")[:3000].lower()
            return r.status_code, r.url, body
        except Exception:
            return None, url, ""

    def _assess_s3(self, bucket, timeout_seconds):
        url = f"https://{bucket}.s3.amazonaws.com/"
        status, final_url, body = self._probe(url, timeout_seconds)
        if status is None:
            return None
        if status == 200 and ("listbucketresult" in body or "<contents>" in body):
            return {"provider": "s3", "bucket": bucket, "url": final_url, "status": status, "public": True, "signal": "bucket_listing_enabled", "confidence": 95}
        if status in (200, 403) and "accessdenied" in body:
            return {"provider": "s3", "bucket": bucket, "url": final_url, "status": status, "public": False, "signal": "bucket_exists_access_denied", "confidence": 55}
        if status == 404 and ("nosuchbucket" in body or "not found" in body):
            return None
        return None

    def _assess_gcs(self, bucket, timeout_seconds):
        url = f"https://storage.googleapis.com/{bucket}/"
        status, final_url, body = self._probe(url, timeout_seconds)
        if status is None:
            return None
        if status == 200 and ("<listbucketresult" in body or "xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\"" in body):
            return {"provider": "gcs", "bucket": bucket, "url": final_url, "status": status, "public": True, "signal": "bucket_listing_enabled", "confidence": 95}
        if status in (401, 403) and ("access denied" in body or "anonymous caller" in body):
            return {"provider": "gcs", "bucket": bucket, "url": final_url, "status": status, "public": False, "signal": "bucket_exists_restricted", "confidence": 55}
        return None

    def _assess_azure(self, bucket, timeout_seconds):
        # For Azure, candidate is used as account and common container names are tested.
        account = re.sub(r"[^a-z0-9]", "", bucket.lower())[:24]
        if len(account) < 3:
            return None
        containers = ["public", "assets", "media", "static", "files", "backup"]
        for container in containers:
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            status, final_url, body = self._probe(url, timeout_seconds)
            if status == 200 and ("<enumerationresults" in body or "<blobs>" in body):
                return {
                    "provider": "azure_blob",
                    "bucket": f"{account}/{container}",
                    "url": final_url,
                    "status": status,
                    "public": True,
                    "signal": "container_listing_enabled",
                    "confidence": 90,
                }
            if status in (403, 409) and ("authenticationfailed" in body or "public access is not permitted" in body):
                return {
                    "provider": "azure_blob",
                    "bucket": f"{account}/{container}",
                    "url": final_url,
                    "status": status,
                    "public": False,
                    "signal": "container_exists_restricted",
                    "confidence": 50,
                }
        return None

    def run(self):
        domain = str(self.target).strip().lower()
        if not domain:
            print_error("target is required")
            return {"error": "target is required"}

        timeout_seconds = self._to_int(self.timeout, 8)
        max_candidates = self._to_int(self.max_candidates, 80)
        candidates = self._build_candidates(domain)[:max_candidates]

        print_info(f"Hunting public cloud buckets for {domain}")
        print_info(f"Candidates generated: {len(candidates)}")

        findings = []
        for cand in candidates:
            s3 = self._assess_s3(cand, timeout_seconds)
            if s3:
                findings.append(s3)

            gcs = self._assess_gcs(cand, timeout_seconds)
            if gcs:
                findings.append(gcs)

            az = self._assess_azure(cand, timeout_seconds)
            if az:
                findings.append(az)

        # Deduplicate on provider+bucket+signal
        unique = {}
        for f in findings:
            key = (f.get("provider"), f.get("bucket"), f.get("signal"))
            unique[key] = f
        findings = list(unique.values())
        if not self.include_restricted:
            findings = [f for f in findings if f.get("public")]

        public_count = len([f for f in findings if f.get("public")])
        risk_level = "LOW"
        if public_count >= 3:
            risk_level = "HIGH"
        elif public_count >= 1:
            risk_level = "MEDIUM"

        data = {
            "target": domain,
            "candidates_tested": len(candidates),
            "count": len(findings),
            "public_count": public_count,
            "risk_level": risk_level,
            "findings": sorted(
                findings,
                key=lambda x: (
                    not x.get("public", False),
                    -int(x.get("confidence", 0)),
                    x.get("provider", ""),
                ),
            ),
        }

        if findings:
            print_warning(
                f"Bucket findings: {len(findings)} (public={public_count}, risk={risk_level})"
            )
            for f in data["findings"][:20]:
                print_info(
                    f"  [{f['provider']}] {f['bucket']} | public={f['public']} "
                    f"| status={f['status']} | signal={f['signal']}"
                )
        else:
            print_success("No bucket exposure signal found in tested candidates")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        target = data.get("target", self.target)
        nodes = []
        edges = []
        for i, f in enumerate(data.get("findings", [])[:20]):
            nid = f"bucket_{i}_{target}"
            icon = "🪣" if f.get("public") else "🔒"
            label = f"{f.get('provider')}:{f.get('bucket')} ({f.get('confidence', 0)})"
            group = "hostname" if f.get("public") else "generic"
            nodes.append({"id": nid, "label": label, "group": group, "icon": icon})
            edges.append({"from": target, "to": nid, "label": "bucket"})
        return nodes, edges
