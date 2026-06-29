from kittysploit import *
import json
import re
from urllib.parse import quote
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "GitHub Org Exposure Scanner",
        "author": ["KittySploit Team"],
        "description": (
            "Discover public GitHub repositories tied to a target domain/org, scan README "
            "and workflow files for secret patterns, and surface CI/CD misconfigurations."
        ),
        "tags": ["osint", "passive", "github", "secrets", "supply-chain"],
    }

    target = OptString("", "Target domain or GitHub org name (e.g. example.com or acme-corp)", required=True)
    github_token = OptString("", "Optional GitHub personal access token (raises rate limits)", required=False)
    max_repos = OptString("25", "Maximum repositories to analyze", required=False)
    timeout = OptString("12", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    SECRET_PATTERNS = [
        ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b")),
        ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")),
        ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")),
        ("database_url", re.compile(r"(?i)(mysql|postgres|mongodb)(\+srv)?://[^\s'\"]+")),
    ]

    WORKFLOW_RISK_HINTS = [
        ("pull_request_target", re.compile(r"pull_request_target")),
        ("unpinned_action", re.compile(r"uses:\s*[^@\s]+@[a-f0-9]{7,40}\b")),
        ("curl_pipe_bash", re.compile(r"curl\s+[^\s|]+\s*\|\s*(ba)?sh")),
        ("hardcoded_secret", re.compile(r"(?i)(password|secret|token)\s*:\s*['\"][^'\"]{6,}['\"]")),
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _api_headers(self):
        headers = {
            "User-Agent": "KittyOSINT/1.0",
            "Accept": "application/vnd.github+json",
        }
        token = str(self.github_token or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _http_get_host(self, host, path, timeout_seconds, headers=None):
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = 443
            self.ssl = True
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
                headers=headers or {},
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _normalize_target(self, value):
        raw = str(value).strip().lower()
        raw = re.sub(r"^https?://", "", raw)
        raw = raw.split("/", 1)[0].strip(".")
        if not raw:
            return None, []
        org_candidates = set()
        if "." in raw:
            apex = raw.split(".", 1)[0]
            org_candidates.add(apex)
            org_candidates.add(apex.replace("-", ""))
            org_candidates.add(raw.replace(".", "-"))
        else:
            org_candidates.add(raw)
        return raw, sorted(org_candidates)

    def _search_repos(self, query, per_page, timeout_seconds):
        path = f"/search/repositories?q={quote(query)}&per_page={per_page}&sort=updated"
        resp = self._http_get_host("api.github.com", path, timeout_seconds, self._api_headers())
        if not resp or resp.status_code != 200:
            return []
        try:
            return resp.json().get("items", [])
        except Exception:
            return []

    def _org_repos(self, org, per_page, timeout_seconds):
        path = f"/orgs/{quote(org)}/repos?per_page={per_page}&sort=updated"
        resp = self._http_get_host("api.github.com", path, timeout_seconds, self._api_headers())
        if not resp:
            return []
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            return []
        try:
            data = resp.json()
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _fetch_text(self, url, timeout_seconds):
        parsed_host = url.split("/", 3)
        if len(parsed_host) < 4:
            return ""
        host = parsed_host[2]
        path = "/" + parsed_host[3]
        resp = self._http_get_host(host, path, timeout_seconds, {"User-Agent": "KittyOSINT/1.0"})
        if not resp or resp.status_code != 200:
            return ""
        return (resp.text or "")[:80000]

    def _scan_secrets(self, text):
        hits = []
        for name, pattern in self.SECRET_PATTERNS:
            for match in pattern.finditer(text):
                snippet = match.group(0)[:80]
                redacted = snippet[:4] + "…" + snippet[-4:] if len(snippet) > 12 else "…"
                hits.append({"type": name, "snippet_redacted": redacted})
                if len(hits) >= 10:
                    return hits
        return hits

    def _scan_workflows(self, owner, repo, timeout_seconds):
        path = f"/repos/{owner}/{repo}/contents/.github/workflows"
        resp = self._http_get_host("api.github.com", path, timeout_seconds, self._api_headers())
        if not resp or resp.status_code != 200:
            return []
        try:
            files = resp.json()
        except Exception:
            return []
        if not isinstance(files, list):
            return []

        risks = []
        for wf in files[:8]:
            name = wf.get("name", "")
            download = wf.get("download_url")
            if not download:
                continue
            content = self._fetch_text(download, timeout_seconds)
            if not content:
                continue
            for risk_name, pattern in self.WORKFLOW_RISK_HINTS:
                if pattern.search(content):
                    risks.append({"workflow": name, "risk": risk_name})
        return risks

    def _repo_finding(self, repo, timeout_seconds):
        full_name = repo.get("full_name", "")
        owner = repo.get("owner", {}).get("login", "")
        name = repo.get("name", "")
        default_branch = repo.get("default_branch", "main")
        html_url = repo.get("html_url", "")

        readme_urls = [
            f"https://raw.githubusercontent.com/{full_name}/{default_branch}/README.md",
            f"https://raw.githubusercontent.com/{full_name}/master/README.md",
        ]
        readme_text = ""
        for url in readme_urls:
            readme_text = self._fetch_text(url, timeout_seconds)
            if readme_text:
                break

        secret_hits = self._scan_secrets(readme_text)
        workflow_risks = self._scan_workflows(owner, name, timeout_seconds)

        risk_score = 0
        if secret_hits:
            risk_score += 40 + min(30, len(secret_hits) * 10)
        if workflow_risks:
            risk_score += 20 + min(25, len(workflow_risks) * 8)
        if repo.get("fork"):
            risk_score += 5
        if repo.get("archived"):
            risk_score += 10

        return {
            "full_name": full_name,
            "url": html_url,
            "description": (repo.get("description") or "")[:200],
            "default_branch": default_branch,
            "stars": repo.get("stargazers_count", 0),
            "fork": bool(repo.get("fork")),
            "archived": bool(repo.get("archived")),
            "secret_hits": secret_hits,
            "workflow_risks": workflow_risks,
            "risk_score": min(100, risk_score),
        }

    def run(self):
        domain, org_candidates = self._normalize_target(self.target)
        if not domain:
            print_error("target is required")
            return {"error": "invalid target"}

        max_repos = self._to_int(self.max_repos, 25)
        timeout_seconds = self._to_int(self.timeout, 12)

        print_info(f"Searching GitHub exposure for: {domain}")
        repos_by_name = {}

        for org in org_candidates[:3]:
            print_status(f"Checking org: {org}")
            for repo in self._org_repos(org, max_repos, timeout_seconds):
                full_name = repo.get("full_name")
                if full_name:
                    repos_by_name[full_name] = repo

        search_queries = [
            f'"{domain}" in:readme,description',
            f"{domain} in:name,description",
        ]
        for query in search_queries:
            for repo in self._search_repos(query, max_repos, timeout_seconds):
                full_name = repo.get("full_name")
                if full_name:
                    repos_by_name[full_name] = repo

        repos = list(repos_by_name.values())[:max_repos]
        if not repos:
            print_warning("No public GitHub repositories found for target")
            return {
                "target": domain,
                "org_candidates": org_candidates,
                "repo_count": 0,
                "risk_level": "NONE",
                "findings": [],
            }

        print_status(f"Analyzing {len(repos)} repository(ies)...")
        findings = []
        for repo in repos:
            findings.append(self._repo_finding(repo, timeout_seconds))

        findings.sort(key=lambda x: -x.get("risk_score", 0))
        high_risk = [f for f in findings if f.get("risk_score", 0) >= 50]
        risk_level = "HIGH" if high_risk else ("MEDIUM" if findings else "LOW")

        data = {
            "target": domain,
            "org_candidates": org_candidates,
            "repo_count": len(findings),
            "high_risk_count": len(high_risk),
            "risk_level": risk_level,
            "findings": findings,
        }

        print_success(
            f"GitHub scan: {len(findings)} repo(s), high_risk={len(high_risk)} (level={risk_level})"
        )
        for f in findings[:10]:
            flags = []
            if f.get("secret_hits"):
                flags.append(f"secrets={len(f['secret_hits'])}")
            if f.get("workflow_risks"):
                flags.append(f"workflow_risks={len(f['workflow_risks'])}")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            print_info(f"  [{f.get('risk_score')}] {f.get('full_name')}{flag_str}")

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
        for i, f in enumerate(data.get("findings", [])[:15]):
            if f.get("risk_score", 0) < 30:
                continue
            nid = f"github_{i}"
            nodes.append({
                "id": nid,
                "label": f"{f.get('full_name')} (risk={f.get('risk_score')})",
                "group": "repo",
                "icon": "🐙",
            })
            edges.append({"from": target, "to": nid, "label": "github"})
        return nodes, edges
