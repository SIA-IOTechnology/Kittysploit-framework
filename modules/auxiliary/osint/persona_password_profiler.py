from kittysploit import *
import json
import os
import re
from urllib.parse import urlparse

from core.osint.password_profiling import (
    apply_rdap_company_name,
    build_scored_password_candidates,
    build_username_candidates_from_intel,
    merge_intel_from_files,
    parse_target,
)
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Persona Password Profiler",
        "author": ["KittySploit Team"],
        "description": (
            "Collect OSINT on a person (name/email) or company (domain), then propose "
            "20 contextually relevant password candidates for authorized assessments."
        ),
        "tags": ["osint", "identity", "password", "persona", "wordlist"],
    }

    target = OptString(
        "",
        "Person full name, email address, or company domain",
        required=True,
    )
    target_type = OptString(
        "auto",
        "Target type: auto|person|email|company",
        required=False,
    )
    company_domain = OptString(
        "",
        "Company domain when profiling a person (e.g. acme.com)",
        required=False,
    )
    identity_file = OptString(
        "",
        "Optional JSON output from identity_handle_hunter",
        required=False,
    )
    email_file = OptString(
        "",
        "Optional JSON output from email_pattern_harvester",
        required=False,
    )
    password_count = OptString("20", "Number of password suggestions to return", required=False)
    fetch_rdap = OptBool(True, "Fetch RDAP org name for company targets", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)
    wordlist_file = OptString("", "Optional plaintext wordlist (one password per line)", required=False)
    usernames_wordlist_file = OptString(
        "",
        "Optional username wordlist for login bruteforce (emails and handles)",
        required=False,
    )

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _load_json(self, path):
        if not path:
            return {}
        try:
            with open(str(path), "r") as fp:
                data = json.load(fp)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

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

    def _fetch_rdap(self, domain, timeout_seconds):
        if not domain:
            return {}
        url = f"https://rdap.org/domain/{domain}"
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200:
            return {}
        try:
            return resp.json()
        except Exception:
            return {}

    def _infer_company_domain(self, intel):
        if self.company_domain:
            return str(self.company_domain).strip().lower()
        if intel.domains:
            return intel.domains[0]
        if intel.target_type == "email" and intel.emails:
            return intel.emails[0].split("@", 1)[1]
        if intel.target_type == "company":
            return intel.raw_target.lower()
        return ""

    def _ensure_parent_dir(self, path):
        parent = os.path.dirname(str(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def run(self):
        target = str(self.target).strip()
        company_domain = str(self.company_domain or "").strip()
        if not target and company_domain:
            target = company_domain
        if not target:
            print_error("target is required (person name, email, or company domain)")
            return {"error": "target is required"}

        password_count = self._to_int(self.password_count, 20)
        timeout_seconds = self._to_int(self.timeout, 10)

        print_info(f"Profiling target: {target}")
        intel = parse_target(target, str(self.target_type or "auto"))
        intel = merge_intel_from_files(
            intel,
            identity_data=self._load_json(self.identity_file),
            email_data=self._load_json(self.email_file),
            company_domain=str(self.company_domain or ""),
        )

        company_domain = self._infer_company_domain(intel)
        if self.fetch_rdap and company_domain:
            print_status(f"Fetching RDAP for {company_domain}...")
            rdap = self._fetch_rdap(company_domain, timeout_seconds)
            intel = apply_rdap_company_name(intel, rdap)

        passwords = build_scored_password_candidates(intel, count=password_count)
        usernames = build_username_candidates_from_intel(intel, count=24)

        data = {
            "target": target,
            "target_type": intel.target_type,
            "company_domain": company_domain,
            "intel_summary": {
                "full_name": intel.full_name,
                "first_name": intel.first_name,
                "last_name": intel.last_name,
                "company_name": intel.company_name,
                "company_token": intel.company_token,
                "handles": intel.handles[:10],
                "emails": intel.emails[:10],
                "platforms": intel.platforms[:8],
                "sources": intel.sources,
            },
            "password_count": len(passwords),
            "username_count": len(usernames),
            "usernames": usernames,
            "passwords": passwords,
        }

        print_info("=" * 72)
        print_success(f"Intel collected - type={intel.target_type}, sources={', '.join(intel.sources[:6])}")
        if intel.full_name:
            print_info(f"  Person: {intel.full_name}")
        if intel.company_name or intel.company_token:
            print_info(f"  Company: {intel.company_name or intel.company_token} ({company_domain or 'n/a'})")
        if intel.handles:
            print_info(f"  Handles: {', '.join(intel.handles[:5])}")
        if intel.platforms:
            print_info(f"  Platforms: {', '.join(intel.platforms[:5])}")

        print_info("-" * 72)
        print_success(f"{len(passwords)} password candidate(s):")
        for idx, row in enumerate(passwords, start=1):
            print_info(
                f"  {idx:2d}. [{row.get('score'):3d}] {row.get('password')} "
                f"- {row.get('rationale')}"
            )

        if self.output_file:
            try:
                self._ensure_parent_dir(self.output_file)
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"JSON results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save JSON output: {e}")

        if self.wordlist_file:
            try:
                self._ensure_parent_dir(self.wordlist_file)
                with open(str(self.wordlist_file), "w") as fp:
                    for row in passwords:
                        pwd = str(row.get("password", "")).strip()
                        if pwd:
                            fp.write(pwd + "\n")
                print_success(f"Password wordlist saved to {self.wordlist_file}")
            except Exception as e:
                print_error(f"Failed to save password wordlist: {e}")

        if self.usernames_wordlist_file:
            try:
                self._ensure_parent_dir(self.usernames_wordlist_file)
                with open(str(self.usernames_wordlist_file), "w") as fp:
                    for user in usernames:
                        value = str(user).strip()
                        if value:
                            fp.write(value + "\n")
                print_success(f"Username wordlist saved to {self.usernames_wordlist_file}")
            except Exception as e:
                print_error(f"Failed to save username wordlist: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        target = data.get("target", self.target)
        nodes = []
        edges = []
        summary = data.get("intel_summary") or {}
        label_parts = []
        if summary.get("full_name"):
            label_parts.append(summary["full_name"])
        if summary.get("company_name"):
            label_parts.append(summary["company_name"])
        root_id = f"persona_{target}"
        nodes.append({
            "id": root_id,
            "label": " / ".join(label_parts) or target,
            "group": "person",
            "icon": "👤",
        })
        for i, row in enumerate(data.get("passwords", [])[:12]):
            nid = f"pwd_{i}"
            nodes.append({
                "id": nid,
                "label": f"{row.get('password')} ({row.get('score')})",
                "group": "signal",
                "icon": "🔑",
            })
            edges.append({"from": root_id, "to": nid, "label": row.get("rationale", "guess")})
        return nodes, edges
