from kittysploit import *
import json
import re
from urllib.parse import urlparse

from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Terraform State Exposure Detector",
        "author": ["KittySploit Team"],
        "description": (
            "Passive detection of Terraform state exposure indicators: tfstate paths/URLs, remote backends "
            "(S3, GCS, Azure, HTTP, Consul, Terraform Cloud), and bucket or state file names in fetched text."
        ),
        "tags": ["osint", "terraform", "iac", "cloud", "passive"],
    }

    target = OptString("", "Target domain, base URL, or keyword label for this run", required=True)
    sources = OptString("", "Comma-separated source URLs to scan (repos, paste, CI logs, mirrors)", required=False)
    probe_state_paths = OptBool(
        False,
        "If target looks like a host, also GET common tfstate paths on https/http root",
        required=False,
    )
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    _STATE_PATH_HINTS = (
        "/terraform.tfstate",
        "/tf/terraform.tfstate",
        "/infra/terraform.tfstate",
        "/.terraform/terraform.tfstate",
        "/state/terraform.tfstate",
        "/state/default.tfstate",
        "/terraform/state",
        "/backend.tfstate",
    )

    TFSTATE_IN_URL_RX = re.compile(
        r"(?i)\b(?:https?://[^\s\"'<>]+|s3://[^\s\"'<>]+|gs://[^\s\"'<>]+|[^\s\"'<>]*\.tfstate[^\s\"'<>]*)\b"
    )
    S3_STATE_RX = re.compile(r"\bs3://([a-z0-9][a-z0-9.\-_]{1,253}[a-z0-9])/([^\s\"'<>]{1,512})\b", re.I)
    GCS_STATE_RX = re.compile(r"\bgs://([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])/([^\s\"'<>]{1,512})\b", re.I)
    AZURE_STATE_RX = re.compile(
        r"(?i)\bhttps?://([a-z0-9\-]{3,24})\.blob\.core\.windows\.net/[^\s\"'<>]+\.tfstate\b"
    )
    TFC_URL_RX = re.compile(r"(?i)\bhttps?://app\.terraform\.io/[^\s\"'<>]+")
    TFC_HOSTNAME_BLOCK_RX = re.compile(
        r'(?is)hostname\s*=\s*["\']app\.terraform\.io["\']',
    )
    BACKEND_S3_BLOCK_RX = re.compile(
        r'(?is)backend\s+["\']s3["\']\s*\{[^}]{0,8000}?bucket\s*=\s*["\']([^"\']+)["\'][^}]{0,8000}?key\s*=\s*["\']([^"\']+)["\']',
    )
    BACKEND_S3_KEY_BUCKET_RX = re.compile(
        r'(?is)backend\s+["\']s3["\']\s*\{[^}]{0,8000}?key\s*=\s*["\']([^"\']+)["\'][^}]{0,8000}?bucket\s*=\s*["\']([^"\']+)["\']',
    )
    KEY_TFSTATE_RX = re.compile(r'(?i)\bkey\s*=\s*["\']([^"\']*\.tfstate[^"\']*)["\']')
    HTTP_BACKEND_RX = re.compile(r'(?i)backend\s+["\']http["\']\s*\{[^}]{0,4000}?address\s*=\s*["\']([^"\']+)["\']')
    CONSUL_BACKEND_RX = re.compile(
        r'(?i)backend\s+["\']consul["\']\s*\{[^}]{0,4000}?address\s*=\s*["\']([^"\']+)["\']'
    )
    ETCD_BACKEND_RX = re.compile(r'(?i)backend\s+["\']etcdv3["\']\s*\{[^}]{0,4000}?endpoints\s*=\s*\[([^\]]+)\]')

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

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
            self.ssl = scheme == "https"
            return self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _normalize_host(self, value):
        s = str(value).strip().lower().replace("https://", "").replace("http://", "")
        s = s.split("/", 1)[0].strip(".")
        if not s or "." not in s or " " in s:
            return None
        return s

    def _collect_urls(self):
        src = [x.strip() for x in str(self.sources).split(",") if x.strip()]
        host = self._normalize_host(self.target)
        timeout_seconds = self._to_int(self.timeout, 10)

        if src:
            return src, timeout_seconds

        if not host:
            return [], timeout_seconds

        roots = [f"https://{host}", f"http://{host}"]
        out = list(roots)
        if self.probe_state_paths:
            for root in roots:
                base = root.rstrip("/")
                for p in self._STATE_PATH_HINTS:
                    path = p if p.startswith("/") else f"/{p}"
                    out.append(f"{base}{path}")
        return out, timeout_seconds

    def _looks_like_state_json(self, text):
        if not text or len(text) < 80:
            return False
        low = text.lstrip()[:4000]
        if '"resources"' not in low and "'resources'" not in low:
            return False
        markers = ('"version"', '"terraform_version"', '"serial"', '"lineage"')
        return sum(1 for m in markers if m in low) >= 2

    def _score(self, finding):
        kind = finding.get("kind", "")
        score = 2
        if kind == "likely_state_json_body":
            score = 10
        elif kind in ("s3_backend_block", "gcs_uri", "s3_uri", "azure_blob_state_url"):
            score = 8
        elif kind in ("http_backend_address", "terraform_cloud_ref", "consul_backend"):
            score = 7
        elif kind == "tfstate_url_in_text":
            score = 6
        elif kind in ("key_tfstate_assignment", "etcd_backend"):
            score = 5
        detail = str(finding.get("detail", "")).lower()
        if any(x in detail for x in ("prod", "production", "live", "master", "admin", "secret")):
            score = min(10, score + 1)
        return score

    def _scan_body(self, body, source_url):
        findings = []
        if not body:
            return findings

        if self._looks_like_state_json(body):
            findings.append({
                "kind": "likely_state_json_body",
                "detail": "Body matches Terraform state JSON shape (version/resources/serial/lineage)",
                "source": source_url,
            })

        for m in self.TFSTATE_IN_URL_RX.findall(body):
            if ".tfstate" in m.lower() or "terraform.tfstate" in m.lower():
                findings.append({"kind": "tfstate_url_in_text", "detail": m[:500], "source": source_url})

        for bucket, key in self.S3_STATE_RX.findall(body):
            findings.append({
                "kind": "s3_uri",
                "detail": f"s3://{bucket}/{key[:400]}",
                "source": source_url,
            })

        for bucket, key in self.GCS_STATE_RX.findall(body):
            findings.append({
                "kind": "gcs_uri",
                "detail": f"gs://{bucket}/{key[:400]}",
                "source": source_url,
            })

        for acct in self.AZURE_STATE_RX.findall(body):
            findings.append({
                "kind": "azure_blob_state_url",
                "detail": f"account={acct}",
                "source": source_url,
            })

        tfc_url = self.TFC_URL_RX.search(body)
        if tfc_url:
            findings.append(
                {"kind": "terraform_cloud_ref", "detail": tfc_url.group(0)[:500], "source": source_url}
            )
        elif self.TFC_HOSTNAME_BLOCK_RX.search(body):
            findings.append(
                {"kind": "terraform_cloud_ref", "detail": "hostname=app.terraform.io (remote backend block)", "source": source_url}
            )

        for b, k in self.BACKEND_S3_BLOCK_RX.findall(body):
            findings.append({"kind": "s3_backend_block", "detail": f"bucket={b} key={k[:400]}", "source": source_url})
        for k, b in self.BACKEND_S3_KEY_BUCKET_RX.findall(body):
            findings.append({"kind": "s3_backend_block", "detail": f"bucket={b} key={k[:400]}", "source": source_url})

        for k in self.KEY_TFSTATE_RX.findall(body):
            findings.append({"kind": "key_tfstate_assignment", "detail": k[:400], "source": source_url})

        for addr in self.HTTP_BACKEND_RX.findall(body):
            findings.append({"kind": "http_backend_address", "detail": addr[:500], "source": source_url})

        for addr in self.CONSUL_BACKEND_RX.findall(body):
            findings.append({"kind": "consul_backend", "detail": addr[:500], "source": source_url})

        if self.ETCD_BACKEND_RX.search(body):
            findings.append({"kind": "etcd_backend", "detail": "etcdv3 endpoints block", "source": source_url})

        return findings

    def run(self):
        urls, timeout_seconds = self._collect_urls()
        if not urls:
            print_error("Provide sources= URLs or a domain target with optional probe_state_paths")
            return {"error": "no_urls", "target": str(self.target).strip()}

        print_info(f"Terraform state exposure scan: {len(urls)} URL(s)")

        all_findings = []
        http_meta = []

        for u in urls:
            resp = self._http_get_url(u, timeout_seconds)
            meta = {"url": u, "status_code": getattr(resp, "status_code", None)}
            http_meta.append(meta)
            if not resp or not resp.text:
                continue
            body = resp.text
            meta["bytes"] = len(body)
            if resp.status_code == 200 and self._looks_like_state_json(body):
                meta["warning"] = "response_body_looks_like_tf_state"
            for f in self._scan_body(body, u):
                f["score"] = self._score(f)
                all_findings.append(f)

        dedup = {}
        for f in all_findings:
            key = f"{f.get('kind')}:{f.get('detail','')[:200]}"
            if key not in dedup or f.get("score", 0) > dedup[key].get("score", 0):
                dedup[key] = f

        findings = sorted(dedup.values(), key=lambda x: int(x.get("score", 0)), reverse=True)
        max_score = max((int(x.get("score", 0)) for x in findings), default=0)
        risk_level = "LOW" if max_score <= 4 else ("MEDIUM" if max_score <= 7 else "HIGH")

        data = {
            "target": str(self.target).strip(),
            "urls_fetched": urls,
            "count_findings": len(findings),
            "max_score": max_score,
            "risk_level": risk_level,
            "findings": findings,
            "http": http_meta,
        }

        print_success(
            f"Terraform exposure indicators: findings={data['count_findings']} max_score={max_score} risk={risk_level}"
        )

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("error"):
            return [], []
        root = data.get("target", self.target)
        nodes, edges = [], []
        for i, f in enumerate(data.get("findings", [])[:30]):
            nid = f"tf_{i}_{root}"
            label = f"{f.get('kind', '?')}: {str(f.get('detail', ''))[:48]}"
            nodes.append({"id": nid, "label": label, "group": "iac", "icon": "📦"})
            edges.append({"from": root, "to": nid, "label": str(f.get("score", ""))})
        return nodes, edges
