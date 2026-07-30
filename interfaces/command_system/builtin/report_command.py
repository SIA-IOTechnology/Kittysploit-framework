#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Report command — push engagement data to KittySploit Reports SaaS.
"""

import argparse
import getpass
import json
import os
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table


class ReportCommand(BaseCommand):
    """Command to push results to KittySploit Reports SaaS"""

    @property
    def name(self) -> str:
        return "report"

    @property
    def description(self) -> str:
        return "Push results (hosts, vulnerabilities, etc.) to KittySploit Reports"

    @property
    def usage(self) -> str:
        return (
            "report [--tuto] [--api-key <key>] [--list] [--use <n>] [--project <id>] "
            "[--push|--push-hosts|--push-vulns|--push-evidence|--push-all] [--yes] [--status] [--config]"
        )

    @property
    def help_text(self) -> str:
        return """
Push results to KittySploit Reports (app.kittysploit.com)

Interactive flow (recommended):
    report --push
      1. Enter your vault passphrase LOCALLY (never sent to the SaaS)
      2. See a table of in-progress reports
      3. Type the number, confirm, data is pushed

Options:
    --tuto              Step-by-step tutorial (API key, list, push, E2EE)
    --api-key <key>     Set or update your API key (saved to config)
    --list              List reports/projects you can push to
    --use <n>           Select report by number from the live list (saved)
    --project <id>      Select report/project by id (saved)
    --push              Interactive push (or push to saved --project)
    --push-hosts        Push hosts only
    --push-vulns        Push vulnerabilities only
    --push-evidence     Push scanner evidence loot (HTTP/request artifacts)
    --push-all          Same as --push (hosts + vulns + evidence)
    --yes               Skip confirmation prompt
    --status            Check connection / API key
    --config            Show current configuration

Examples:
    report --api-key YOUR_KEY
    report --list
    report --use 2
    report --push
    report --push-evidence --yes
    report --project abc123 --push --yes
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
        self.reports_url = "https://app.kittysploit.com"
        self.api_key = None
        self.project_id = None
        self.project_name = None
        self._passphrase = None  # memory only — never persisted, never uploaded
        self.config_file = os.path.join(
            os.path.expanduser("~"),
            ".kittysploit",
            "report_config.json"
        )
        self._legacy_config_file = os.path.join(
            os.path.expanduser("~"),
            ".kittysploit",
            "portal_config.json"
        )
        self._load_config()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="Push results to KittySploit Reports",
            add_help=True
        )
        parser.add_argument('--tuto', action='store_true', help='Show step-by-step tutorial')
        parser.add_argument('--api-key', dest='api_key', help='Set or update API key')
        parser.add_argument('--list', action='store_true', help='List available reports/projects')
        parser.add_argument('--use', dest='use_index', type=int, help='Select report by list number')
        parser.add_argument('--project', dest='project', help='Select report/project by id')
        parser.add_argument('--push', action='store_true', help='Push all hosts and vulnerabilities')
        parser.add_argument('--push-hosts', action='store_true', help='Push all hosts to Reports')
        parser.add_argument('--push-vulns', action='store_true', help='Push all vulnerabilities')
        parser.add_argument('--push-evidence', action='store_true', help='Push scanner evidence loot')
        parser.add_argument('--push-all', action='store_true', help='Push all hosts, vulnerabilities, and evidence')
        parser.add_argument('--yes', '-y', action='store_true', help='Skip confirmation prompt')
        parser.add_argument('--status', action='store_true', help='Check connection status and API key')
        parser.add_argument('--config', action='store_true', help='Show current configuration')
        return parser

    def _load_config(self):
        """Load report configuration from file (migrates legacy portal config)."""
        try:
            config_path = self.config_file
            if not os.path.exists(config_path) and os.path.exists(self._legacy_config_file):
                config_path = self._legacy_config_file

            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key')
                    self.project_id = config.get('project_id')
                    self.project_name = config.get('project_name')
                    url = config.get('reports_url') or config.get('portal_url')
                    if url:
                        self.reports_url = url

                if config_path == self._legacy_config_file and self.api_key:
                    self._save_config()
        except Exception:
            pass

    def _save_config(self):
        """Save report configuration to file (never stores the passphrase)."""
        try:
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir, mode=0o700)

            config = {
                'api_key': self.api_key,
                'reports_url': self.reports_url,
                'project_id': self.project_id,
                'project_name': self.project_name,
                'updated_at': datetime.now().isoformat()
            }

            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)

            os.chmod(self.config_file, 0o600)
        except Exception as e:
            print_error(f"Error saving configuration: {e}")

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True

        if args and args[0].lower() in ['help', '--help', '-h']:
            self.parser.print_help()
            return True

        try:
            if parsed_args.tuto:
                return self._show_tuto()

            want_push = (
                parsed_args.push or parsed_args.push_all
                or parsed_args.push_hosts or parsed_args.push_vulns
                or parsed_args.push_evidence
            )
            want_list = parsed_args.list or parsed_args.use_index is not None

            if parsed_args.api_key:
                if not self._set_api_key(
                    parsed_args.api_key,
                    test_connection=not (want_push or want_list or parsed_args.status
                                         or parsed_args.project or parsed_args.config)
                ):
                    return False
                if not (want_push or want_list or parsed_args.status
                        or parsed_args.project or parsed_args.config):
                    return True

            if parsed_args.project:
                if not self._set_project_by_id(parsed_args.project):
                    return False
                if not want_push and not want_list and not parsed_args.status:
                    return True

            if parsed_args.list and parsed_args.use_index is None and not want_push:
                return self._list_reports(unlock=False)

            if parsed_args.use_index is not None and not want_push:
                return self._use_report_index(parsed_args.use_index, unlock=False)

            if parsed_args.status:
                return self._check_status()
            if parsed_args.config:
                return self._show_config()

            if want_push:
                push_all = parsed_args.push or parsed_args.push_all
                return self._interactive_or_direct_push(
                    push_hosts=parsed_args.push_hosts or push_all,
                    push_vulns=parsed_args.push_vulns or push_all,
                    push_evidence=parsed_args.push_evidence or push_all,
                    skip_confirm=parsed_args.yes,
                    prefer_index=parsed_args.use_index,
                )

            self.parser.print_help()
            return True

        except Exception as e:
            print_error(f"Error executing report command: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _show_tuto(self) -> bool:
        print_success("report")
        print_info("Push hosts and vulnerabilities to KittySploit Reports.")
        print_info("")
        print_info("Setup")
        print_info("  1. Create an API key in Reports (app.kittysploit.com).")
        print_info("  2. Save it once:")
        print_info("       report --api-key <KEY>")
        print_info("     Stored in ~/.kittysploit/report_config.json (permissions 600).")
        print_info("")
        print_info("Push")
        print_info("  report --push")
        print_info("  - Enter the vault passphrase when prompted (local only).")
        print_info("  - Pick a report from the list by number.")
        print_info("  - Confirm to upload the current workspace data.")
        print_info("")
        print_info("Other commands")
        print_info("  report --list              List available reports")
        print_info("  report --use <n>           Set target report by list number")
        print_info("  report --project <id>      Set target report by id")
        print_info("  report --push --yes        Push without confirmation")
        print_info("  report --status            Check API connectivity")
        print_info("  report --config            Show local configuration")
        print_info("  export [-o file.json]      Offline JSON export for manual Reports import")
        print_info("")
        print_info("Security")
        print_info("  - API key: authentication only; saved locally.")
        print_info("  - Passphrase: never stored and never sent to the server.")
        print_info("  - Engagement data is sealed client-side (E2EE); the SaaS")
        print_info("    stores ciphertext and cannot read findings in plaintext.")
        print_info("")
        return True

    def _set_api_key(self, api_key: str, test_connection: bool = True) -> bool:
        if not api_key or len(api_key.strip()) == 0:
            print_error("API key cannot be empty")
            return False

        self.api_key = api_key.strip()
        self._save_config()
        print_success(f"API key saved to {self.config_file}")
        if test_connection:
            print_info("Testing connection...")
            return self._check_status()
        return True

    def _prompt_passphrase(self) -> bool:
        """Ask for vault passphrase. Kept in memory only — never uploaded."""
        print_info("Vault passphrase (local only — never sent to Reports SaaS)")
        try:
            pw = getpass.getpass("Passphrase: ")
        except (EOFError, KeyboardInterrupt):
            print_error("Cancelled")
            return False
        if not pw:
            print_error("Passphrase cannot be empty")
            return False
        self._passphrase = pw
        print_success("Local vault unlocked for this command (passphrase not transmitted)")
        return True

    def _auth_headers(self) -> Dict[str, str]:
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'KittySploit-Framework/1.0.0'
        }

    def _require_api_key(self) -> bool:
        if self.api_key:
            return True
        print_error("API key not set. Use 'report --api-key <key>' (see report --tuto)")
        return False

    def _normalize_report_item(self, item: Dict, fallback_index: int = 0) -> Dict[str, Any]:
        rid = (
            item.get('id')
            or item.get('project_id')
            or item.get('uuid')
            or item.get('report_id')
            or str(fallback_index)
        )
        name = (
            item.get('name')
            or item.get('title')
            or item.get('client_name')
            or item.get('label')
            or f"Report {rid}"
        )
        client = item.get('client_name') or item.get('client') or item.get('organization') or "-"
        status = item.get('status') or item.get('state') or "unknown"
        updated = (
            item.get('updated_at')
            or item.get('last_updated')
            or item.get('modified_at')
            or item.get('created_at')
            or "-"
        )
        return {
            'id': str(rid),
            'name': str(name),
            'client': str(client),
            'status': str(status),
            'updated': str(updated),
            'raw': item,
        }

    def _fetch_reports(self) -> List[Dict[str, Any]]:
        """Fetch report/project list via API key (metadata only)."""
        endpoints = (
            "/api/v1/reports",
            "/api/v1/projects",
            "/api/v1/engagements",
        )
        last_error = None
        for path in endpoints:
            try:
                response = requests.get(
                    f"{self.reports_url}{path}",
                    headers=self._auth_headers(),
                    timeout=15,
                    params={'status': 'in_progress'},
                )
                if response.status_code == 401:
                    print_error("Authentication failed. Check your API key.")
                    return []
                if response.status_code == 404:
                    continue
                if response.status_code != 200:
                    last_error = f"{path} → HTTP {response.status_code}"
                    continue

                data = response.json()
                if isinstance(data, list):
                    raw_items = data
                elif isinstance(data, dict):
                    raw_items = (
                        data.get('reports')
                        or data.get('projects')
                        or data.get('engagements')
                        or data.get('data')
                        or data.get('items')
                        or []
                    )
                else:
                    raw_items = []

                if not isinstance(raw_items, list):
                    continue

                return [
                    self._normalize_report_item(item if isinstance(item, dict) else {'name': str(item)}, i)
                    for i, item in enumerate(raw_items, start=1)
                ]
            except requests.exceptions.RequestException as e:
                last_error = str(e)
                continue

        if last_error:
            print_warning(f"Could not list reports ({last_error})")
        return []

    def _print_reports_table(self, reports: List[Dict[str, Any]]) -> None:
        headers = ["#", "ID", "Name", "Client", "Status", "Updated"]
        rows = [
            [str(i), r['id'][:16], r['name'][:40], r['client'][:24], r['status'][:16], r['updated'][:19]]
            for i, r in enumerate(reports, start=1)
        ]
        print_table(headers, rows)

    def _list_reports(self, unlock: bool = False) -> bool:
        if not self._require_api_key():
            return False
        if unlock and not self._prompt_passphrase():
            return False

        print_info("Fetching reports...")
        reports = self._fetch_reports()
        if not reports:
            print_warning("No reports found (or API list endpoint not available yet)")
            return True

        print_success(f"Found {len(reports)} report(s)")
        self._print_reports_table(reports)
        if self.project_id:
            print_info(f"Current target: {self.project_name or self.project_id} ({self.project_id})")
        print_info("Select with: report --use <n>   or   report --push")
        return True

    def _use_report_index(self, index: int, unlock: bool = False) -> bool:
        if not self._require_api_key():
            return False
        if unlock and not self._prompt_passphrase():
            return False
        if index < 1:
            print_error("Index must be >= 1")
            return False

        reports = self._fetch_reports()
        if not reports:
            print_warning("No reports found")
            return False
        if index > len(reports):
            print_error(f"Invalid number {index} (list has {len(reports)} entries)")
            self._print_reports_table(reports)
            return False

        chosen = reports[index - 1]
        return self._persist_project(chosen['id'], chosen['name'])

    def _set_project_by_id(self, project_id: str) -> bool:
        project_id = (project_id or "").strip()
        if not project_id:
            print_error("Project id cannot be empty")
            return False
        name = project_id
        if self.api_key:
            for item in self._fetch_reports():
                if item['id'] == project_id:
                    name = item['name']
                    break
        return self._persist_project(project_id, name)

    def _persist_project(self, project_id: str, project_name: str) -> bool:
        self.project_id = project_id
        self.project_name = project_name
        self._save_config()
        print_success(f"Target report set: {project_name} ({project_id})")
        return True

    def _pick_report_interactively(self, prefer_index: Optional[int] = None) -> Optional[Dict[str, Any]]:
        reports = self._fetch_reports()
        if not reports:
            print_warning("No reports found — create one in KittySploit Reports first")
            return None

        self._print_reports_table(reports)

        if prefer_index is not None:
            if 1 <= prefer_index <= len(reports):
                return reports[prefer_index - 1]
            print_error(f"Invalid number {prefer_index}")

        if self.project_id:
            for item in reports:
                if item['id'] == self.project_id:
                    print_info(f"Saved target is #{reports.index(item) + 1}: {item['name']}")
                    break

        try:
            raw = input("Select report number (q to cancel): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print_error("Cancelled")
            return None

        if raw in ("q", "quit", "cancel", ""):
            print_warning("Cancelled")
            return None

        try:
            index = int(raw)
        except ValueError:
            print_error("Please enter a number")
            return None

        if index < 1 or index > len(reports):
            print_error(f"Invalid number {index}")
            return None
        return reports[index - 1]

    def _confirm(self, message: str, skip: bool = False) -> bool:
        if skip:
            return True
        try:
            answer = input(f"{message} [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print_error("Cancelled")
            return False
        return answer in ("y", "yes")

    def _interactive_or_direct_push(
        self,
        push_hosts: bool,
        push_vulns: bool,
        push_evidence: bool = False,
        skip_confirm: bool = False,
        prefer_index: Optional[int] = None,
    ) -> bool:
        if not self._require_api_key():
            return False

        # Same UX as requested: passphrase → table → number → confirm → push
        # Passphrase stays local (E2EE). List is fetched with API key.
        if not self._prompt_passphrase():
            return False

        print_info("Loading in-progress reports...")
        chosen = self._pick_report_interactively(prefer_index=prefer_index)
        if not chosen:
            return False

        self._persist_project(chosen['id'], chosen['name'])

        if not self._confirm(
            f"Push workspace data to « {chosen['name']} » ?",
            skip=skip_confirm,
        ):
            print_warning("Push cancelled")
            return False

        return self._push_selected(
            push_hosts=push_hosts,
            push_vulns=push_vulns,
            push_evidence=push_evidence,
        )

    def _push_selected(
        self,
        push_hosts: bool,
        push_vulns: bool,
        push_evidence: bool = False,
    ) -> bool:
        print_info(f"Pushing to report: {self.project_name or self.project_id}")
        print_info("")
        ok = True
        if push_hosts:
            ok = self._push_hosts() and ok
            print_info("")
        if push_vulns:
            ok = self._push_vulnerabilities() and ok
            print_info("")
        if push_evidence:
            ok = self._push_evidence() and ok
        if ok:
            print_success("Push completed")
        else:
            print_warning("Push finished with errors")
        # Drop passphrase from memory after the operation
        self._passphrase = None
        return ok

    def _show_config(self) -> bool:
        print_info("Reports Configuration")
        print_info("=" * 80)
        print_info(f"Reports URL: {self.reports_url}")
        if self.api_key:
            masked_key = f"{self.api_key[:8]}...{self.api_key[-4:]}" if len(self.api_key) > 12 else "***"
            print_info(f"API Key: {masked_key}")
        else:
            print_warning("API Key: Not set")
        if self.project_id:
            print_info(f"Target report: {self.project_name or '-'} ({self.project_id})")
        else:
            print_warning("Target report: Not set (will ask on --push)")
        print_info("Passphrase: never stored in config (prompted locally when needed)")
        print_info(f"Config File: {self.config_file}")
        print_info("=" * 80)
        return True

    def _check_status(self) -> bool:
        if not self._require_api_key():
            return False

        print_info("Checking connection to Reports...")
        try:
            response = requests.get(
                f"{self.reports_url}/api/v1/status",
                headers=self._auth_headers(),
                timeout=10
            )

            if response.status_code == 200:
                print_success("Connection successful!")
                try:
                    data = response.json()
                    if 'user' in data:
                        print_info(f"Authenticated as: {data.get('user', {}).get('email', 'Unknown')}")
                    if 'workspace' in data:
                        print_info(f"Workspace: {data.get('workspace', {}).get('name', 'Unknown')}")
                except Exception:
                    pass
                if self.project_id:
                    print_info(f"Target report: {self.project_name or self.project_id}")
                return True
            if response.status_code == 401:
                print_error("Authentication failed. Please check your API key")
                return False
            print_warning(f"Unexpected response: {response.status_code}")
            print_info(f"Response: {response.text[:200]}")
            return False

        except requests.exceptions.ConnectionError:
            print_error("Failed to connect to Reports. Please check your internet connection")
            return False
        except requests.exceptions.Timeout:
            print_error("Connection timeout. Please try again later")
            return False
        except Exception as e:
            print_error(f"Error checking status: {e}")
            return False

    def _get_db_session(self):
        if not hasattr(self.framework, 'get_db_session'):
            return None
        return self.framework.get_db_session()

    def _push_hosts(self) -> bool:
        if not self._require_api_key():
            return False
        if not self.project_id:
            print_error("No target report selected")
            return False

        session = self._get_db_session()
        if not session:
            print_error("Database not available")
            return False

        try:
            from core.models.models import Host

            current_workspace = self.framework.workspace_manager.get_current_workspace() if hasattr(self.framework, 'workspace_manager') else None
            if not current_workspace:
                print_error("No workspace found")
                return False

            hosts = session.query(Host).filter(Host.workspace_id == current_workspace.id).all()
            if not hosts:
                print_warning("No hosts found in current workspace")
                return True

            print_info(f"Found {len(hosts)} hosts to push...")
            from core.scanner.finding_report import vulnerability_to_kittyreport_finding

            hosts_data = []
            for host in hosts:
                host_dict = host.to_dict()
                if hasattr(host, 'services'):
                    host_dict['services'] = [s.to_dict() for s in host.services]
                if hasattr(host, 'vulnerabilities'):
                    host_dict['vulnerabilities'] = [
                        vulnerability_to_kittyreport_finding(v)
                        for v in host.vulnerabilities
                    ]
                hosts_data.append(host_dict)

            return self._send_to_reports('hosts', hosts_data)

        except Exception as e:
            print_error(f"Error pushing hosts: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _push_vulnerabilities(self) -> bool:
        if not self._require_api_key():
            return False
        if not self.project_id:
            print_error("No target report selected")
            return False

        session = self._get_db_session()
        if not session:
            print_error("Database not available")
            return False

        try:
            from core.models.models import Vulnerability, Host, host_vulnerabilities

            current_workspace = self.framework.workspace_manager.get_current_workspace() if hasattr(self.framework, 'workspace_manager') else None
            if not current_workspace:
                print_error("No workspace found")
                return False

            vulnerabilities = session.query(Vulnerability).join(
                host_vulnerabilities
            ).join(
                Host
            ).filter(
                Host.workspace_id == current_workspace.id
            ).distinct().all()

            if not vulnerabilities:
                print_warning("No vulnerabilities found in current workspace")
                return True

            print_info(f"Found {len(vulnerabilities)} vulnerabilities to push...")
            from core.scanner.finding_report import vulnerability_to_kittyreport_finding

            vulns_data = []
            for vuln in vulnerabilities:
                vuln_dict = vulnerability_to_kittyreport_finding(vuln)
                if hasattr(vuln, 'hosts'):
                    vuln_dict['hosts'] = [h.to_dict() for h in vuln.hosts]
                vulns_data.append(vuln_dict)

            return self._send_to_reports('vulnerabilities', vulns_data)

        except Exception as e:
            print_error(f"Error pushing vulnerabilities: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _push_evidence(self) -> bool:
        """Push scanner evidence loot (schema Evidence JSON) to Reports."""
        if not self._require_api_key():
            return False
        if not self.project_id:
            print_error("No target report selected")
            return False

        session = self._get_db_session()
        if not session:
            print_error("Database not available")
            return False

        try:
            from core.models.models import Loot, Host

            current_workspace = (
                self.framework.workspace_manager.get_current_workspace()
                if hasattr(self.framework, "workspace_manager")
                else None
            )
            if not current_workspace:
                print_error("No workspace found")
                return False

            loots = (
                session.query(Loot)
                .filter(
                    Loot.workspace_id == current_workspace.id,
                    Loot.loot_type.in_(("evidence", "screenshot")),
                )
                .all()
            )
            if not loots:
                print_warning("No evidence loot found in current workspace")
                return True

            print_info(f"Found {len(loots)} evidence item(s) to push...")
            evidence_data: List[Dict[str, Any]] = []
            for loot in loots:
                item = loot.to_dict()
                host = None
                if loot.host_id:
                    host = session.query(Host).filter(Host.id == loot.host_id).first()
                if host is not None:
                    item["host"] = host.to_dict()

                payload = None
                raw = loot.content
                if raw:
                    try:
                        payload = json.loads(raw) if isinstance(raw, str) else raw
                    except Exception:
                        payload = raw
                if loot.file_path and str(loot.loot_type or "").lower() == "screenshot":
                    try:
                        from core.scanner.screenshot import screenshot_to_data_url

                        data_url = screenshot_to_data_url(loot.file_path)
                        payload = {
                            "kind": "screenshot",
                            "screenshot": loot.file_path,
                            "file_path": loot.file_path,
                            "file_size": loot.file_size,
                        }
                        if data_url:
                            payload["screenshot_data_url"] = data_url
                    except Exception:
                        payload = {"kind": "screenshot", "screenshot": loot.file_path}
                elif payload is None and loot.file_path:
                    path = loot.file_path
                    if not os.path.isabs(path):
                        path = os.path.join(os.getcwd(), path)
                    try:
                        if os.path.isfile(path):
                            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                                payload = json.load(handle)
                    except Exception:
                        payload = None

                item["evidence"] = payload
                item["workspace"] = current_workspace.name
                evidence_data.append(item)

            return self._send_to_reports("evidence", evidence_data)

        except Exception as e:
            print_error(f"Error pushing evidence: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _send_to_reports(self, endpoint: str, data: List[Dict]) -> bool:
        """Send data to Reports API. Passphrase is never included in the payload."""
        try:
            payload = {
                'data': data,
                'project_id': self.project_id,
                'workspace': self.framework.workspace_manager.get_current_workspace().name if hasattr(self.framework, 'workspace_manager') else 'default',
                'timestamp': datetime.now().isoformat(),
                'framework_version': self.framework.version if hasattr(self.framework, 'version') else '1.0.0'
            }
            # Intentionally omit passphrase / crypto key from the request.

            print_info(f"Sending {len(data)} {endpoint} → project {self.project_id}...")

            response = requests.post(
                f"{self.reports_url}/api/v1/{endpoint}/sync",
                headers=self._auth_headers(),
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                print_success(f"Successfully pushed {len(data)} {endpoint}")
                try:
                    result = response.json()
                    if 'message' in result:
                        print_info(result['message'])
                    if 'created' in result:
                        print_info(f"Created: {result['created']}")
                    if 'updated' in result:
                        print_info(f"Updated: {result['updated']}")
                except Exception:
                    pass
                return True
            if response.status_code == 401:
                print_error("Authentication failed. Please check your API key")
                return False
            if response.status_code == 400:
                print_error(f"Bad request: {response.text[:200]}")
                return False
            print_error(f"Failed to push data: {response.status_code}")
            print_info(f"Response: {response.text[:200]}")
            return False

        except requests.exceptions.ConnectionError:
            print_error("Failed to connect to Reports. Please check your internet connection")
            return False
        except requests.exceptions.Timeout:
            print_error("Connection timeout. Please try again later")
            return False
        except Exception as e:
            print_error(f"Error sending data to Reports: {e}")
            return False
