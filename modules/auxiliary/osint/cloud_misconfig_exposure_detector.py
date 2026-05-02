from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Cloud Misconfig Exposure Detector",
        "author": ["KittySploit Team"],
        "description": "Identify likely exposed AWS/Azure/GCP cloud resources from passive URL and naming signals.",
        "tags": ["osint", "cloud", "misconfig", "passive"],
    }

    target = OptString("", "Target domain/keyword", required=True)
    sources = OptString("", "Comma-separated source URLs (HTML/JS/text) to inspect", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    AWS_BUCKET_RX = re.compile(r"\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b", re.I)
    AZURE_BLOB_RX = re.compile(r"\b([a-z0-9\-]{3,24})\.blob\.core\.windows\.net\b", re.I)
    GCP_BUCKET_RX = re.compile(r"\bstorage\.googleapis\.com\/([a-z0-9][a-z0-9.\-_]{1,220})\b", re.I)
    IAM_HINT_RX = re.compile(r"(?i)\b(iam|role|policy|assumeRole|serviceAccount|managedIdentity|access[_-]?key|secret[_-]?key)\b")

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
            self.ssl = (scheme == "https")
            return self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _score_asset(self, provider, name, context):
        score = 1
        if provider in ("aws", "azure", "gcp"):
            score += 2
        low = f"{name} {context}".lower()
        if any(k in low for k in ["backup", "prod", "internal", "private", "secret", "archive"]):
            score += 2
        if str(self.target).lower() in low:
            score += 2
        return min(10, score)

    def run(self):
        src = [x.strip() for x in str(self.sources).split(",") if x.strip()]
        if not src:
            normalized = str(self.target).strip().lower().replace("https://", "").replace("http://", "").split("/", 1)[0]
            if "." in normalized and " " not in normalized:
                src = [f"https://{normalized}", f"http://{normalized}"]
            else:
                src = []
        timeout_seconds = self._to_int(self.timeout, 10)
        assets = []
        iam_signals = []
        if not src:
            print_status("No explicit sources provided; skipping cloud exposure crawl")
            return {
                "target": str(self.target).strip(),
                "count_assets": 0,
                "count_iam_signals": 0,
                "risk_score": 0,
                "risk_level": "LOW",
                "assets": [],
                "iam_signals": [],
                "skipped": True,
                "reason": "no_sources",
            }
        print_info(f"Cloud exposure passive analysis for {len(src)} source(s)")

        for u in src:
            resp = self._http_get_url(u, timeout_seconds)
            if not resp or resp.status_code != 200 or not resp.text:
                continue
            body = resp.text

            for bucket in self.AWS_BUCKET_RX.findall(body):
                assets.append({
                    "provider": "aws",
                    "asset_type": "s3_bucket",
                    "name": bucket,
                    "source": u,
                })
            for account in self.AZURE_BLOB_RX.findall(body):
                assets.append({
                    "provider": "azure",
                    "asset_type": "blob_account",
                    "name": account,
                    "source": u,
                })
            for bucket in self.GCP_BUCKET_RX.findall(body):
                assets.append({
                    "provider": "gcp",
                    "asset_type": "gcs_bucket",
                    "name": bucket,
                    "source": u,
                })
            if self.IAM_HINT_RX.search(body):
                iam_signals.append({"source": u, "signal": "iam_or_secret_keyword_detected"})

        dedup = {}
        for a in assets:
            key = f"{a['provider']}:{a['asset_type']}:{a['name']}"
            if key not in dedup:
                dedup[key] = a
                dedup[key]["score"] = self._score_asset(a["provider"], a["name"], a.get("source", ""))
        selected_assets = sorted(dedup.values(), key=lambda x: int(x.get("score", 0)), reverse=True)

        risk_score = min(10, len(selected_assets) + (2 if iam_signals else 0))
        risk_level = "LOW" if risk_score <= 2 else ("MEDIUM" if risk_score <= 5 else "HIGH")
        data = {
            "target": str(self.target).strip(),
            "count_assets": len(selected_assets),
            "count_iam_signals": len(iam_signals),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "assets": selected_assets,
            "iam_signals": iam_signals,
        }
        print_success(
            f"Cloud exposure analysis done: assets={data['count_assets']} iam_signals={data['count_iam_signals']} risk={risk_level}"
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
        if not isinstance(data, dict) or "error" in data:
            return [], []
        root = data.get("target", self.target)
        nodes, edges = [], []
        for i, a in enumerate(data.get("assets", [])[:25]):
            nid = f"cloud_{i}_{root}"
            icon = "☁️"
            if a.get("provider") == "aws":
                icon = "🟧"
            elif a.get("provider") == "azure":
                icon = "🟦"
            elif a.get("provider") == "gcp":
                icon = "🟥"
            nodes.append({
                "id": nid,
                "label": f"{a.get('provider')}:{a.get('name')}",
                "group": "cloud",
                "icon": icon,
            })
            edges.append({"from": root, "to": nid, "label": a.get("asset_type", "asset")})
        return nodes, edges
