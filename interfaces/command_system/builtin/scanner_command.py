#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner command implementation - Execute all scanner modules against a target URL
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import (
    print_info,
    print_success,
    print_error,
    print_warning,
    print_table,
    print_empty,
    print_progress,
    end_progress,
    print_status,
    set_thread_output_quiet,
    color_red,
    color_yellow,
    color_blue,
    color_green,
)
from urllib.parse import urlparse
import threading
import socket
import time
from contextvars import copy_context
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set, Optional, Tuple
import errno
import re

from core.scanner.result_dedup import (
    deduplicate_scanner_results,
    enrich_scanner_result,
    group_scanner_results,
)
from core.scanner.probe_failure import is_soft_probe_failure
from core.framework.module_executor import ModuleExecutionRequest, ModuleExecutor


_CVE_RE = re.compile(r"CVE-(\d{4})-(\d{3,7})", re.IGNORECASE)
# Follow-up modules shown in the findings table (not the scanner detect itself).
_FOLLOWUP_PREFIXES = ("exploit/", "exploits/", "auxiliary/")


class ScannerCommand(BaseCommand):
    """Command to execute all scanner modules against a target URL"""

    def _format_severity(self, severity: Optional[str]) -> str:
        """Return a colorized severity label for quick visual scanning."""
        if not severity:
            return ""

        sev = str(severity).strip()
        sev_lower = sev.lower()

        if sev_lower in ("critical", "crit"):
            return color_red(sev)
        if sev_lower == "high":
            return color_red(sev)
        if sev_lower in ("medium", "moderate"):
            return color_yellow(sev)
        if sev_lower == "low":
            return color_blue(sev)
        if sev_lower == "info":
            return color_green(sev)

        return sev
    
    @property
    def name(self) -> str:
        return "scanner"
    
    @property
    def description(self) -> str:
        return "Execute all scanner modules against a target URL"
    
    @property
    def usage(self) -> str:
        return (
            "scanner -u <URL|HOSTNAME:PORT> [--protocol PROTO] [--tags TAG1,TAG2] "
            "[--port PORT] [--threads N] [--module MODULE] [--scan-ports] "
            "[--auto-exploit] [--evidence] [--screenshots]"
        )
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command automatically discovers and executes all scanner modules
against the specified target URL.

Options:
    -u, --url URL        Target URL to scan (required, or use hostname:port)
    --protocol PROTO     Filter by protocol (http, ftp, ssh, etc.)
    --tags TAG1,TAG2     Filter by tags (comma-separated, e.g., ssh,apache)
    --port PORT          Specify target port (overrides URL port)
    --scan-ports         Enable automatic port scanning (default: enabled if no filters)
    --no-scan-ports      Disable automatic port scanning
    --auto-exploit       Automatically launch exploit modules after vulnerability detection
    --threads N          Number of concurrent threads (default: 10)
    --module MODULE      Execute only a specific module (e.g., http/apache_version_check)
    --all                Include panel/CVE/mass-detect modules (noisy/slow; off by default)
    --list               List all available scanner modules
    --verbose, -v        Show detailed output for each module
    --no-cache           Disable HTTP request caching
    --no-dedup           Disable grouping/deduplication of identical findings
    --no-save            Do not auto-save vulnerable findings to the workspace DB
    --no-stack-gate      Disable stack fingerprint gating (run CMS/SPA modules blindly)
    --evidence           Capture HTTP/request evidence for vulnerable hits (disk + DB loot)
    --screenshots        Capture headless page screenshots for hits (implies --evidence; needs Playwright)

By default only low-noise checks run (HTTP methods, security/headers, banners,
non-HTTP services). Product/panel fingerprints are opt-in.
Stack gating skips WordPress/Joomla/Drupal/Next.js/React modules when the
target shows no evidence of that stack (saves requests/time; use --no-stack-gate
to disable).

Examples:
    scanner -u https://example.com
    scanner -u https://example.com --evidence
    scanner -u https://example.com --evidence --screenshots
    scanner -u https://example.com --tags panel
    scanner -u https://example.com --all
    scanner -u http://192.168.1.100 --threads 10
    scanner -u https://example.com --module http/apache_version_check
    scanner -u example.com --protocol http
    scanner -u example.com --tags ssh --port 2222
    scanner -u example.com --tags cve
    scanner -u example.com --scan-ports
    scanner --list
    # Cloud (AWS S3, Azure, GCP, K8s, metadata):
    scanner -u https://bucket.s3.region.amazonaws.com --protocol cloud
    scanner -u https://storage.blob.core.windows.net --module cloud/aws_s3_detect
    # Telecom / 5G (GTP, Diameter, PFCP, management):
    scanner -u 10.0.0.1 --port 3868 --module telecom/diameter_port_detect
    scanner -u 10.0.0.1 --port 2152 --module telecom/gtp_udp_detect
    scanner -u https://oss.example.com --protocol telecom
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the scanner command"""
        try:
            raw = list(args or [])
            if (
                not raw
                or raw[0].lower() in ("help", "--help", "-h")
                or "--help" in raw
                or "-h" in raw
            ):
                print_info(self.help_text)
                return True

            # Parse arguments
            options = self._parse_args(raw)
            
            if options['list']:
                return self._list_modules()
            
            if not options['url']:
                print_error("URL is required. Use -u or --url to specify target URL")
                print_info(f"Usage: {self.usage}")
                print_info(f"Use 'scanner --help' for more information")
                return False
            
            # Parse target (URL or hostname:port)
            target_info = self._parse_target(options['url'], options.get('port'))
            if not target_info:
                print_error(f"Invalid target: {options['url']}")
                return False
            
            # Discover scanner modules (static metadata only — no import)
            print_info("Discovering scanner modules...")
            modules = self._discover_modules()
            
            if not modules:
                print_warning("No scanner modules found")
                return False
            print_info(f"Indexed {len(modules)} scanner module(s)")
            
            # Filter by module if specified
            if options['module']:
                modules = [m for m in modules if options['module'] in m['path']]
                if not modules:
                    print_error(f"Module '{options['module']}' not found")
                    return False
            
            # Filter by protocol/tags if specified
            if options.get('protocol') or options.get('tags'):
                modules = self._filter_modules(modules, options.get('protocol'), options.get('tags'))
                if not modules:
                    print_warning("No modules match the specified filters")
                    return False
                
                # If port specified with tags/protocol, also filter by port
                if target_info.get('port'):
                    modules = self._filter_modules_by_ports(modules, [target_info['port']])
                    if not modules:
                        print_warning(f"No modules available for port {target_info['port']} with specified filters")
                        return False
            
            # If no protocol/module/tags specified, auto-scan ports and filter modules
            elif not options.get('protocol') and not options.get('module') and not options.get('tags'):
                # Auto-scan ports by default (unless explicitly disabled with --no-scan-ports)
                if options.get('scan_ports', True):  # Default to True if not explicitly set
                    print_info("Scanning ports to detect services...")
                    scan_result = self._scan_ports(target_info['hostname'], target_info.get('port'))
                    open_ports = scan_result.get("open_ports", [])
                    if open_ports:
                        print_info(f"Open ports detected: {', '.join(map(str, open_ports))}")
                        target_info['open_ports'] = open_ports
                        # Filter modules based on detected ports
                        modules = self._filter_modules_by_ports(modules, open_ports)
                        if not modules:
                            print_warning("No modules available for detected ports")
                            return False
                    else:
                        if scan_result.get("resolution_error"):
                            print_warning(
                                f"Host does not respond (name resolution failed): {scan_result['resolution_error']}"
                            )
                        elif not scan_result.get("host_responsive", False):
                            print_warning(
                                "Host does not respond on scanned ports (timeout/unreachable)."
                            )
                        else:
                            print_warning("No open ports detected")
                        return False
                elif target_info.get('port'):
                    # If scan disabled but port specified, use that port
                    modules = self._filter_modules_by_ports(modules, [target_info['port']])
                    if not modules:
                        print_warning(f"No modules available for port {target_info['port']}")
                        return False

            # Mass CVE modules are opt-in (otherwise default scans take hours)
            modules = self._apply_default_module_scope(modules, options)
            
            print_info(f"Found {len(modules)} scanner module(s)")
            print_info(f"Target: {target_info['hostname']}:{target_info.get('port', 'default')}")
            if options.get('protocol'):
                print_info(f"Protocol filter: {options['protocol']}")
            if options.get('tags'):
                print_info(f"Tags filter: {options['tags']}")
            print_info(f"Threads: {options['threads']}")
            
            # Réinitialiser le cache au début du scan
            try:
                from lib.scanner.cache import reset_cache, get_cache, enable_cache, disable_cache
                
                if options.get('no_cache', False):
                    disable_cache()
                    print_info("Cache disabled")
                else:
                    enable_cache()
                    reset_cache()
                    cache = get_cache()
                    print_info(f"Cache enabled (TTL: {cache._ttl}s)")
            except ImportError:
                pass

            if options.get("screenshots"):
                options["evidence"] = True

            if options.get("evidence"):
                try:
                    from core.scanner.evidence_capture import evidence_dir_for_scan

                    ws_name = "default"
                    try:
                        if hasattr(self.framework, "get_current_workspace_name"):
                            ws_name = self.framework.get_current_workspace_name() or "default"
                        elif hasattr(self.framework, "workspace_manager"):
                            current = self.framework.workspace_manager.get_current_workspace()
                            if current is not None:
                                ws_name = getattr(current, "name", None) or "default"
                    except Exception:
                        ws_name = "default"
                    scan_id, evidence_path = evidence_dir_for_scan(workspace=ws_name)
                    options["evidence_scan_id"] = scan_id
                    options["evidence_dir"] = evidence_path
                    options["evidence_workspace"] = ws_name
                    print_info(f"Evidence capture enabled → {evidence_path}")
                    if options.get("screenshots"):
                        print_info("Screenshots enabled (Playwright/Chromium, post-hit capture)")
                except Exception as exc:
                    print_warning(f"Could not initialize evidence directory: {exc}")
                    options["evidence"] = False
                    options["screenshots"] = False
            
            print_empty()
            
            # Execute modules with shared HTTP pool + path prefetch (P0/P1)
            from lib.scanner.http_pool import scan_http_session

            try:
                from lib.scanner.http.soft_404 import clear_baselines

                clear_baselines()
            except Exception:
                pass

            timing: Dict[str, float] = {}
            scan_t0 = time.perf_counter()
            with scan_http_session(pool_size=max(20, options["threads"] * 2)):
                # Fingerprint `/` (+ cheap CMS confirms) BEFORE prefetch so we do
                # not pull hundreds of WordPress/plugin paths on non-CMS targets.
                if not options.get("no_stack_gate") and not options.get("module"):
                    gate_t0 = time.perf_counter()
                    modules, gate_info = self._apply_stack_gate(
                        modules, target_info, options
                    )
                    timing["stack_gate"] = time.perf_counter() - gate_t0
                    if gate_info.get("skipped"):
                        print_info(
                            f"Stack gate skipped {gate_info['skipped']} module(s) "
                            f"({gate_info.get('summary') or 'no matching stack'})"
                        )
                    if gate_info.get("hints"):
                        print_info(
                            f"Stack fingerprint: {', '.join(gate_info['hints'])}"
                        )
                    if not modules:
                        print_warning("No modules left after stack gating")
                        return False
                    print_info(f"Running {len(modules)} module(s) after stack gate")

                if not options.get("no_cache", False):
                    prefetch_t0 = time.perf_counter()
                    self._prefetch_http_probes(modules, target_info, options["threads"])
                    timing["prefetch"] = time.perf_counter() - prefetch_t0
                exec_t0 = time.perf_counter()
                raw_results = self._execute_modules(
                    modules,
                    target_info,
                    options["threads"],
                    options["verbose"],
                    capture_evidence=bool(options.get("evidence")),
                    evidence_dir=options.get("evidence_dir"),
                    evidence_workspace=options.get("evidence_workspace"),
                )
                timing["execute"] = time.perf_counter() - exec_t0
            timing["total"] = time.perf_counter() - scan_t0

            if options.get('no_dedup'):
                results = raw_results
            else:
                results = deduplicate_scanner_results(raw_results, target_info=target_info)

            if options.get("screenshots") and options.get("evidence_dir"):
                try:
                    from core.scanner.screenshot import attach_screenshots_to_results

                    shot_count, shot_warning = attach_screenshots_to_results(
                        raw_results,
                        evidence_dir=options["evidence_dir"],
                        target_info=target_info,
                    )
                    if shot_warning:
                        print_warning(shot_warning)
                    elif shot_count:
                        print_success(f"Screenshots captured: {shot_count}")
                        # Refresh deduped view so table/entries see screenshot fields
                        if options.get("no_dedup"):
                            results = raw_results
                        else:
                            results = deduplicate_scanner_results(
                                raw_results, target_info=target_info
                            )
                    else:
                        print_info("Screenshots: no capturable HTTP findings")
                except Exception as exc:
                    print_warning(f"Screenshot capture failed: {exc}")
            
            # Display results
            self._display_results(
                results,
                raw_results,
                options['verbose'],
                grouped=not options.get('no_dedup'),
                timing=timing,
                target_info=target_info,
            )

            if options.get("evidence"):
                evidence_count = sum(
                    1
                    for r in raw_results
                    if r.get("vulnerable") and (r.get("schema_evidence") or r.get("evidence_paths"))
                )
                if evidence_count:
                    print_success(
                        f"Evidence captured for {evidence_count} finding(s)"
                        + (
                            f" → {options.get('evidence_dir')}"
                            if options.get("evidence_dir")
                            else ""
                        )
                    )
                else:
                    print_info("Evidence mode on: no vulnerable hits to capture")

            if not options.get("no_save", False):
                self._persist_findings_to_workspace(
                    getattr(self.framework, "last_scanner_findings", None) or []
                )
            
            # Auto-exploit if enabled
            if options.get('auto_exploit'):
                self._auto_exploit(results, target_info)
            
            # Afficher les stats du cache
            if not options.get('no_cache', False):
                try:
                    from lib.scanner.cache import get_cache
                    cache = get_cache()
                    stats = cache.stats()
                    if stats['hits'] > 0 or stats['misses'] > 0:
                        print_empty()
                        print_info("Cache Statistics:")
                        print_info(f"  Hits: {stats['hits']} | Misses: {stats['misses']} | Hit Rate: {stats['hit_rate']}")
                        print_info(f"  Cached requests: {stats['size']}")
                except ImportError:
                    pass
            
            return True
            
        except Exception as e:
            print_error(f"Error executing scanner: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _parse_args(self, args):
        """Parse command line arguments"""
        options = {
            'url': None,
            'protocol': None,
            'tags': None,
            'port': None,
            'scan_ports': True,  # Default: auto-scan ports if no filters
            'auto_exploit': False,  # Auto-launch exploits after detection
            'threads': 10,
            'module': None,
            'list': False,
            'verbose': False,
            'no_cache': False,
            'no_dedup': False,
            'no_save': False,
            'no_stack_gate': False,
            'all': False,
            'evidence': False,
            'screenshots': False,
            'evidence_dir': None,
            'evidence_scan_id': None,
            'evidence_workspace': None,
        }
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg in ['-u', '--url']:
                if i + 1 < len(args):
                    options['url'] = args[i + 1]
                    i += 2
                else:
                    print_error(f"Option {arg} requires a value")
                    i += 1
            elif arg in ['-p', '--protocol']:
                if i + 1 < len(args):
                    options['protocol'] = args[i + 1].lower()
                    i += 2
                else:
                    print_error("--protocol requires a value")
                    i += 1
            elif arg == '--tags':
                if i + 1 < len(args):
                    options['tags'] = [t.strip() for t in args[i + 1].split(',')]
                    i += 2
                else:
                    print_error("--tags requires a value")
                    i += 1
            elif arg == '--port':
                if i + 1 < len(args):
                    try:
                        options['port'] = int(args[i + 1])
                        i += 2
                    except ValueError:
                        print_error("--port requires a number")
                        i += 1
                else:
                    print_error("--port requires a value")
                    i += 1
            elif arg == '--scan-ports':
                options['scan_ports'] = True
                i += 1
            elif arg == '--no-scan-ports':
                options['scan_ports'] = False
                i += 1
            elif arg == '--auto-exploit':
                options['auto_exploit'] = True
                i += 1
            elif arg == '--threads':
                if i + 1 < len(args):
                    try:
                        options['threads'] = int(args[i + 1])
                        i += 2
                    except ValueError:
                        print_error("--threads requires a number")
                        i += 1
                else:
                    print_error("--threads requires a value")
                    i += 1
            elif arg == '--module':
                if i + 1 < len(args):
                    options['module'] = args[i + 1]
                    i += 2
                else:
                    print_error("--module requires a value")
                    i += 1
            elif arg == '--list':
                options['list'] = True
                i += 1
            elif arg in ['-v', '--verbose']:
                options['verbose'] = True
                i += 1
            elif arg == '--no-dedup':
                options['no_dedup'] = True
                i += 1
            elif arg == '--no-save':
                options['no_save'] = True
                i += 1
            elif arg == '--no-cache':
                options['no_cache'] = True
                i += 1
            elif arg == '--no-stack-gate':
                options['no_stack_gate'] = True
                i += 1
            elif arg == '--all':
                options['all'] = True
                i += 1
            elif arg == '--evidence':
                options['evidence'] = True
                i += 1
            elif arg == '--screenshots':
                options['screenshots'] = True
                options['evidence'] = True
                i += 1
            else:
                # Try to interpret as URL if no URL set
                if not options['url'] and (arg.startswith('http://') or arg.startswith('https://') or ':' in arg):
                    options['url'] = arg
                i += 1
        
        return options
    
    def _parse_target(self, target: str, port_override: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Parse target URL or hostname:port format"""
        try:
            # Try URL format first
            if target.startswith('http://') or target.startswith('https://'):
                parsed = urlparse(target)
                hostname = parsed.hostname or parsed.netloc.split(':')[0]
                port = port_override or parsed.port
                if not port:
                    port = 443 if parsed.scheme == 'https' else 80
                scheme = parsed.scheme
                path = parsed.path or '/'
                return {
                    'hostname': hostname,
                    'port': port,
                    'scheme': scheme,
                    'path': path,
                    'url': target
                }
            # Try hostname:port format
            elif ':' in target and not target.startswith('http'):
                parts = target.rsplit(':', 1)
                if len(parts) == 2:
                    try:
                        hostname = parts[0]
                        port = port_override or int(parts[1])
                        mapped = self._port_to_protocol(port)
                        if port == 443:
                            scheme = 'https'
                        elif port == 80:
                            scheme = 'http'
                        elif mapped:
                            scheme = mapped
                        else:
                            scheme = 'http'
                        if scheme in {'http', 'https'}:
                            url = f"{scheme}://{hostname}:{port}/"
                        else:
                            url = f"{scheme}://{hostname}:{port}"
                        return {
                            'hostname': hostname,
                            'port': port,
                            'scheme': scheme,
                            'path': '/',
                            'url': url,
                        }
                    except ValueError:
                        pass
            # Plain hostname
            else:
                port = port_override or 80
                return {
                    'hostname': target,
                    'port': port,
                    'scheme': 'http',
                    'path': '/',
                    'url': f"http://{target}:{port}/"
                }
        except Exception as e:
            return None
        
        return None
    
    def _port_to_protocol(self, port: int) -> Optional[str]:
        """Map port number to protocol name"""
        port_protocol_map = {
            # HTTP
            80: 'http', 443: 'http', 8080: 'http', 8443: 'http', 8000: 'http', 8888: 'http',
            # LDAP / AD
            389: 'ldap', 636: 'ldap',
            # SMB
            445: 'smb', 139: 'smb',
            # FTP
            21: 'ftp', 2121: 'ftp',
            # SSH
            22: 'ssh', 2222: 'ssh', 2223: 'ssh',
            # Telnet
            23: 'telnet',
            # MySQL
            3306: 'mysql',
            # PostgreSQL
            5432: 'postgresql',
            # RDP
            3389: 'rdp',
            # VNC
            5900: 'vnc',
            # SMTP
            25: 'smtp', 587: 'smtp',
            # DNS
            53: 'dns',
            # Telecom / 5G (3GPP)
            3868: 'telecom',   # Diameter
            2123: 'telecom',   # GTP-C
            2152: 'telecom',   # GTP-U
            8805: 'telecom',   # PFCP (5G N4)
        }
        return port_protocol_map.get(port)
    
    def _filter_modules(self, modules: List[Dict], protocol: Optional[str] = None, tags: Optional[List[str]] = None) -> List[Dict]:
        """Filter modules by protocol and/or tags"""
        filtered = modules
        
        if protocol:
            # Filter by protocol (check path like scanner/http/...)
            filtered = [m for m in filtered if f"scanner/{protocol}/" in m['path']]
        
        if tags:
            # Filter by tags (check module tags)
            tag_set = set(t.lower() for t in tags)
            filtered = [m for m in filtered if tag_set.intersection(set(t.lower() for t in m.get('tags', [])))]
        
        return filtered
    
    def _filter_modules_by_ports(self, modules: List[Dict], ports: List[int]) -> List[Dict]:
        """Filter modules based on open ports"""
        # Get protocols for open ports
        protocols = set()
        http_ports = (80, 443, 8080, 8443, 8000, 8888)
        for port in ports:
            proto = self._port_to_protocol(port)
            if proto:
                protocols.add(proto)
            if port in http_ports:
                protocols.add("cloud")   # cloud scanners use HTTP
                protocols.add("telecom")  # telecom management UIs use HTTP
        if not protocols:
            return []
        
        # Filter modules by protocols
        filtered = []
        for module in modules:
            for proto in protocols:
                if f"scanner/{proto}/" in module['path']:
                    filtered.append(module)
                    break
        
        return filtered
    
    def _scan_ports(
        self,
        hostname: str,
        default_port: Optional[int] = None,
        timeout: float = 1.0,
    ) -> Dict[str, Any]:
        """Scan common ports on target hostname and infer basic host responsiveness."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 636, 993, 995, 2123, 2152, 3306, 3389, 3868, 5432, 5900, 8080, 8443, 8805, 2222]

        # If default_port specified, prioritize it
        if default_port and default_port not in common_ports:
            common_ports.insert(0, default_port)

        try:
            socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            return {
                "open_ports": [],
                "host_responsive": False,
                "resolution_error": str(exc),
            }

        open_ports: List[int] = []
        responded = {"value": False}
        lock = threading.Lock()

        refused_codes = {
            getattr(errno, "ECONNREFUSED", 111),
            61,     # macOS fallback
            10061,  # Windows fallback
        }

        def check_port(port: int) -> Tuple[bool, bool]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((hostname, port))
                sock.close()
                is_open = result == 0
                # Connection refused means host responded, even if port is closed.
                host_responded = is_open or result in refused_codes
                return is_open, host_responded
            except:
                return False, False

        # Quick scan with threading
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, port): port for port in common_ports}
            for future in as_completed(futures):
                port = futures[future]
                is_open, host_responded = future.result()
                if is_open:
                    open_ports.append(port)
                if host_responded:
                    with lock:
                        responded["value"] = True

        return {
            "open_ports": sorted(open_ports),
            "host_responsive": responded["value"],
            "resolution_error": None,
        }
    
    def _discover_modules(self) -> List[Dict[str, Any]]:
        """Discover scanner modules via persistent metadata index."""
        try:
            from core.module_index import get_scanner_modules

            discovered = self.framework.module_loader.discover_modules()

            def _progress(done, total, rebuilt, reused):
                print_progress(
                    done,
                    total,
                    label="Indexing",
                    extra=f"parsed={rebuilt} cached={reused}",
                )

            rows = get_scanner_modules(discovered, progress_cb=_progress)
            end_progress()
            return rows
        except Exception as e:
            print_error(f"Error discovering modules: {e}")
            # Fallback: static AST parse without durable index
            modules = []
            try:
                from core.utils.module_static_metadata import extract_module_search_metadata

                discovered = self.framework.module_loader.discover_modules()
                for module_path, file_path in discovered.items():
                    if not module_path.startswith("scanner/"):
                        continue
                    try:
                        module_info = extract_module_search_metadata(file_path) or {}
                        modules.append(
                            {
                                "path": module_path,
                                "file_path": file_path,
                                "name": module_info.get("name") or module_path,
                                "description": module_info.get("description") or "",
                                "author": module_info.get("author") or "",
                                "tags": module_info.get("tags") or [],
                                "cve": module_info.get("cve") or "",
                            }
                        )
                    except Exception:
                        modules.append(
                            {
                                "path": module_path,
                                "file_path": file_path,
                                "name": module_path,
                                "description": "",
                                "author": "",
                                "tags": [],
                                "cve": "",
                            }
                        )
            except Exception as inner:
                print_error(f"Fallback discovery failed: {inner}")
            return sorted(modules, key=lambda x: x["path"])

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Human-readable duration for scan timing output."""
        if seconds < 0:
            seconds = 0.0
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes, sec = divmod(seconds, 60)
        if minutes < 60:
            return f"{int(minutes)}m {sec:.1f}s"
        hours, minutes = divmod(int(minutes), 60)
        return f"{hours}h {minutes}m {sec:.0f}s"

    @staticmethod
    def _is_mass_cve_module(module: Dict[str, Any]) -> bool:
        """True for bulk CVE catalog modules that dominate default scan time."""
        path = str(module.get("path") or "").lower()
        name = path.rsplit("/", 1)[-1]
        return name.startswith("cve_")

    @staticmethod
    def _is_default_skipped_http_module(module: Dict[str, Any]) -> bool:
        """
        Default HTTP surface scan keeps only low-noise checks.

        Product/panel/tech fingerprints are skipped (high FP rate). Opt in with
        ``--tags panel`` / ``--tags tech`` / ``--all``.
        """
        path = str(module.get("path") or "").lower()
        if not path.startswith("scanner/http/"):
            return False
        name = path.rsplit("/", 1)[-1]
        if name.startswith("cve_") or "_cve_" in name:
            return True
        tags = {str(t).lower() for t in (module.get("tags") or [])}

        # Explicit allowlist of hand-written low-noise HTTP helpers
        allowlist = {
            "http_methods_detect",
            "security_headers_detect",
            "server_banner_detect",
            "robots_txt_detect",
            "deprecated_feature_policy_detect",
        }
        if name in allowlist:
            return False

        reliable = {
            "headers",
            "methods",
            "options",
            "allow",
            "hardening",
            "banner",
            "security",
        }
        # Keep only modules explicitly tagged as reliable surface checks
        if tags & reliable and not (
            tags
            & {
                "panel",
                "login",
                "cve",
                "vuln",
                "vulnerability",
                "xss",
                "sqli",
                "rce",
            }
        ):
            return False

        # Everything else under scanner/http is opt-in
        return True

    @staticmethod
    def _is_reliable_http_module(module: Dict[str, Any]) -> bool:
        tags = {str(t).lower() for t in (module.get("tags") or [])}
        reliable = {
            "headers",
            "methods",
            "options",
            "allow",
            "hardening",
            "banner",
            "security",
        }
        return bool(tags & reliable)

    def _apply_default_module_scope(
        self, modules: List[Dict[str, Any]], options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Default ``scanner -u`` skips mass CVE/vuln modules unless explicitly requested.

        Include them with ``--all``, ``--tags cve`` (or other tags), or ``--module ...``.
        """
        if options.get("all") or options.get("module") or options.get("tags"):
            # --tags already filtered the set; still drop pure cve_* unless cve requested
            tags = [str(t).lower() for t in (options.get("tags") or [])]
            if options.get("all") or options.get("module") or "cve" in tags:
                return modules
            # Explicit --tags panel/tech: allow those; still drop CVE catalog unless asked
            kept = [m for m in modules if not self._is_mass_cve_module(m)]
            skipped = len(modules) - len(kept)
            if skipped:
                print_info(
                    f"Skipping {skipped} CVE catalog module(s) "
                    "(use --all or --tags cve to include them)"
                )
            return kept

        kept = []
        skipped = 0
        for module in modules:
            if self._is_default_skipped_http_module(module) or self._is_mass_cve_module(module):
                skipped += 1
                continue
            kept.append(module)

        # Soft cap so a plain ``scanner -u`` stays interactive
        default_cap = 150
        if len(kept) > default_cap:
            def _priority(mod: Dict[str, Any]) -> tuple:
                path = str(mod.get("path") or "")
                family = path.split("/")[1] if "/" in path else ""
                is_http = family == "http"
                # Prefer non-http services, then header/method checks, then the rest
                reliable = 0 if self._is_reliable_http_module(mod) else 1
                return (1 if is_http else 0, reliable, path)

            kept_sorted = sorted(kept, key=_priority)
            capped = len(kept_sorted) - default_cap
            kept = kept_sorted[:default_cap]
            skipped += capped
            print_info(
                f"Capped surface scan to {default_cap} module(s) "
                f"({capped} deferred; use --all for the full catalog)"
            )
        if skipped:
            print_info(
                f"Skipping {skipped} panel/CVE/vuln module(s) for a low-noise surface scan "
                "(use --tags panel, --tags cve, or --all to widen)"
            )
        return kept
    
    def _choose_port_for_module(self, module_path: str, target_info: Dict[str, Any]) -> int:
        """
        Choose the most appropriate port for a scanner module.

        Before this, modules were filtered by detected ports but all of them were still
        executed against ``target_info['port']`` (often 80 by default), which breaks
        non-HTTP scanners like MySQL/Redis/SMB.
        """
        open_ports = target_info.get('open_ports') or []
        configured_port = target_info.get('port')
        if not open_ports:
            return configured_port

        parts = (module_path or "").split("/")
        family = parts[1] if len(parts) > 1 else ""

        # If user explicitly targeted a port and it matches the module family, keep it.
        if configured_port in open_ports:
            proto = self._port_to_protocol(configured_port)
            if proto == family:
                return configured_port
            if family in ("http", "cloud") and configured_port in (80, 443, 8080, 8443, 8000, 8888):
                return configured_port

        if family in ("http", "cloud"):
            preferred = [80, 443, 8080, 8443, 8000, 8888]
        elif family == "mysql":
            preferred = [3306]
        elif family == "redis":
            preferred = [6379]
        elif family == "smb":
            preferred = [445, 139]
        elif family == "ldap":
            preferred = [389, 636]
        elif family == "telecom":
            if self._is_http_telecom_module(module_path):
                if configured_port in open_ports:
                    return configured_port
                preferred = [443, 8443, 8080, 80, 8000, 8888]
            else:
                preferred = [3868, 2123, 2152, 8805, 8080, 8443, 80, 443]
        elif family == "ftp":
            preferred = [21, 2121]
        elif family == "ssh":
            preferred = [22, 2222]
        else:
            preferred = []

        for port in preferred:
            if port in open_ports:
                return port

        # Fallback: first open port whose inferred protocol matches the module family.
        for port in open_ports:
            proto = self._port_to_protocol(port)
            if proto == family:
                return port
            if family in ("http", "cloud") and port in (80, 443, 8080, 8443, 8000, 8888):
                return port

        return configured_port

    # Product-specific HTTP scanners bound to non-standard service ports.
    _MODULE_DEDICATED_PORTS = (
        ("frigate", 5000),
        ("mindsdb", 47334),
        ("n8n_", 5678),
        ("langflow", 7860),
        ("neo4j", 7474),
        ("cassandra", 9042),
        ("cockpit", 9090),
        ("webmin", 10000),
        ("ollama", 11434),
        ("teamcity", 8111),
        ("clickhouse", 8123),
        ("activemq", 8161),
        ("comfyui", 8188),
        ("mlflow", 5000),
        ("splunk", 8000),
        ("kubelet", 10255),
        ("docker_api", 2375),
    )
    _STANDARD_HTTP_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888})

    def _is_http_telecom_module(self, module_path: str) -> bool:
        """HTTP-based telecom scanners (management UIs) should use web ports."""
        path = str(module_path or "").lower()
        return path.startswith("scanner/telecom/") and (
            "management" in path or path.endswith("_detect")
        )

    def _scheme_for_port(self, port: int, target_info: Dict[str, Any]) -> str:
        """Match URL scheme used when modules run (cache key must align)."""
        configured = target_info.get("port")
        target_scheme = str(target_info.get("scheme") or "").lower()
        if configured and int(port) == int(configured) and target_scheme in ("http", "https"):
            return target_scheme
        if int(port) == 443:
            return "https"
        if int(port) == 80:
            return "http"
        if target_scheme in ("http", "https"):
            return target_scheme
        return "https" if int(port) == 443 else "http"

    def _http_ports_for_fingerprint(self, target_info: Dict[str, Any]) -> List[int]:
        """Ports to use for homepage fingerprint (prefer open web ports)."""
        open_ports = list(target_info.get("open_ports") or [])
        configured = target_info.get("port")
        web = [p for p in open_ports if int(p) in self._STANDARD_HTTP_PORTS]
        if configured and int(configured) in self._STANDARD_HTTP_PORTS:
            if int(configured) not in web:
                web.insert(0, int(configured))
            else:
                web = [int(configured)] + [p for p in web if int(p) != int(configured)]
        if not web and configured:
            web = [int(configured)]
        if not web:
            web = [443, 80]
        # Dedupe preserve order
        seen = set()
        out: List[int] = []
        for p in web:
            ip = int(p)
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out[:2]

    def _fetch_http_path(
        self,
        hostname: str,
        port: int,
        path: str,
        scheme: str,
        *,
        timeout: float = 10.0,
    ):
        """GET a path using scan session + response cache when available."""
        from lib.scanner.probe_prefetch import probe_url

        url = probe_url(hostname, port, path, scheme=scheme)
        try:
            from lib.scanner.cache import get_cache, is_cache_enabled

            if is_cache_enabled():
                cached = get_cache().get("GET", url)
                if cached is not None:
                    return cached
        except Exception:
            pass

        try:
            import requests
            from lib.scanner.http_pool import get_scan_session

            session = get_scan_session()
            owns = False
            if session is None:
                session = requests.Session()
                owns = True
            try:
                resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            finally:
                if owns:
                    session.close()
            try:
                from lib.scanner.cache import get_cache, is_cache_enabled

                if is_cache_enabled():
                    get_cache().set("GET", url, resp)
            except Exception:
                pass
            return resp
        except Exception:
            return None

    def _apply_stack_gate(
        self,
        modules: List[Dict[str, Any]],
        target_info: Dict[str, Any],
        options: Dict[str, Any],
    ) -> tuple:
        """
        Fingerprint the HTTP surface, then drop CMS/SPA modules that do not match.

        Returns ``(kept_modules, info_dict)``.
        """
        from lib.scanner.stack_fingerprint import (
            CONFIRM_PATHS,
            apply_confirm_response,
            filter_modules_by_stack,
            fingerprint_http_response,
            merge_fingerprint_kb,
            needed_confirm_families,
            summarize_skips,
        )

        hostname = target_info.get("hostname") or ""
        info: Dict[str, Any] = {
            "skipped": 0,
            "summary": "",
            "hints": [],
        }
        if not hostname:
            return modules, info

        # Only gate when the selected set actually contains specialized modules
        from lib.scanner.stack_fingerprint import families_present_in_modules

        if not families_present_in_modules(modules):
            return modules, info

        kb: Dict[str, Any] = {"tech_hints": [], "tech_confidence": {}}
        ports = self._http_ports_for_fingerprint(target_info)
        print_info("Fingerprinting HTTP stack (homepage + cheap CMS confirms)...")

        for port in ports:
            scheme = self._scheme_for_port(port, target_info)
            resp = self._fetch_http_path(hostname, port, "/", scheme)
            if resp is None:
                continue
            kb = merge_fingerprint_kb(kb, fingerprint_http_response(resp))

        from lib.scanner.stack_fingerprint import confidence_for

        for tech in needed_confirm_families(modules, kb):
            for path in CONFIRM_PATHS.get(tech, ()):
                confirmed = False
                for port in ports:
                    scheme = self._scheme_for_port(port, target_info)
                    resp = self._fetch_http_path(hostname, port, path, scheme)
                    if resp is None:
                        continue
                    before = confidence_for(kb, tech)
                    kb = apply_confirm_response(kb, tech, resp)
                    if confidence_for(kb, tech) > before:
                        confirmed = True
                        break
                if confirmed:
                    break

        kept, skipped = filter_modules_by_stack(modules, kb)
        info["skipped"] = len(skipped)
        info["summary"] = summarize_skips(skipped, modules)
        info["hints"] = list(kb.get("tech_hints") or [])
        if options.get("verbose") and skipped:
            for path, reason in skipped[:12]:
                print_status(f"  skip {path}: {reason}")
            if len(skipped) > 12:
                print_status(f"  ... and {len(skipped) - 12} more")
        return kept, info

    def _prefetch_http_probes(
        self,
        modules: List[Dict[str, Any]],
        target_info: Dict[str, Any],
        threads: int,
    ) -> None:
        """P0/P1: seed ``/`` and prefetch unique GET paths into the response cache."""
        try:
            from lib.scanner.probe_prefetch import collect_module_probes, prefetch_probes
        except ImportError:
            return

        hostname = target_info.get("hostname") or ""
        if not hostname:
            return

        probes = collect_module_probes(
            modules,
            hostname=hostname,
            port_for_module=lambda mp: self._choose_port_for_module(mp, target_info),
            scheme_for_port=lambda port: self._scheme_for_port(port, target_info),
        )
        if not probes:
            return

        print_info(
            f"Prefetching {len(probes)} unique HTTP path(s) "
            f"(seed=/ + soft-404 canary + path grouping)..."
        )

        def _progress(done, total, stats):
            print_progress(
                done,
                total,
                label="Prefetch",
                extra=(
                    f"fetched={stats.get('prefetched', 0)} "
                    f"cached={stats.get('skipped', 0)} "
                    f"err={stats.get('errors', 0)}"
                ),
            )

        t0 = time.perf_counter()
        stats = prefetch_probes(
            probes,
            threads=threads,
            timeout=10.0,
            verify=False,
            progress_cb=_progress if len(probes) > 40 else None,
        )
        end_progress()
        elapsed = time.perf_counter() - t0
        print_info(
            f"Prefetch done: {stats.get('prefetched', 0)} network fetch(es), "
            f"{stats.get('network_fetches', stats.get('prefetched', 0))} unique URL(s), "
            f"{stats.get('skipped', 0)} already cached, "
            f"{stats.get('errors', 0)} error(s) "
            f"in {self._format_duration(elapsed)}"
        )

    def _dedicated_port_for_module(self, module_path: str):
        path = str(module_path or "").lower()
        for marker, port in self._MODULE_DEDICATED_PORTS:
            if marker in path:
                return port
        return None

    def _should_skip_module_for_target(self, module_path: str, target_info: Dict[str, Any]) -> str:
        dedicated = self._dedicated_port_for_module(module_path)
        if dedicated is None:
            return ""
        open_ports = set(target_info.get("open_ports") or [])
        configured = target_info.get("port")
        if configured == dedicated or dedicated in open_ports:
            return ""
        if open_ports and open_ports.issubset(self._STANDARD_HTTP_PORTS):
            return (
                f"skipped: module expects TCP/{dedicated} but only standard web ports are open "
                f"({sorted(open_ports)})"
            )
        return ""

    def _execute_modules(
        self,
        modules: List[Dict],
        target_info: Dict[str, Any],
        threads: int,
        verbose: bool,
        *,
        capture_evidence: bool = False,
        evidence_dir: Optional[str] = None,
        evidence_workspace: Optional[str] = None,
    ) -> List[Dict]:
        """Execute scanner modules against target"""
        results = []

        # P1: keep modules that share the same primary path adjacent
        try:
            from lib.scanner.probe_prefetch import group_modules_by_primary_path

            modules = group_modules_by_primary_path(modules)
        except Exception:
            pass
        
        def execute_module(module_info):
            """Execute a single module"""
            module_path = module_info['path']
            result = {
                'module': module_info['name'],
                'path': module_path,
                'status': 'error',
                'vulnerable': False,
                'message': '',
                'details': {},
                'host': target_info.get('hostname', ''),
            }

            skip_reason = self._should_skip_module_for_target(module_path, target_info)
            if skip_reason:
                result['status'] = 'skipped'
                result['message'] = skip_reason
                return result
            
            try:
                if verbose:
                    print_info(f"[*] Executing: {module_path}")
                set_thread_output_quiet(not verbose)
                try:
                    # Load module (fast=True skips contract/policy AST on bulk runs)
                    module_instance = self.framework.module_loader.load_module(
                        module_path,
                        load_only=False,
                        framework=self.framework,
                        silent=True,
                        fast=True,
                    )

                    if not module_instance:
                        result['message'] = 'Failed to load module'
                        return result

                    # Reset dynamic state when reusing a cached instance
                    if hasattr(module_instance, "vulnerability_info"):
                        module_instance.vulnerability_info = {}
                    # Clear prior HTTP evidence buffer when reusing instances
                    for attr in (
                        "_ks_last_http_response",
                        "_ks_last_http_path",
                        "_ks_last_http_method",
                    ):
                        if hasattr(module_instance, attr):
                            try:
                                setattr(module_instance, attr, None)
                            except Exception:
                                pass

                    # Set target options
                    hostname = target_info['hostname']
                    port = self._choose_port_for_module(module_path, target_info)
                    scheme = self._scheme_for_port(port, target_info)
                    result['port'] = port
                    result['scheme'] = scheme
                    result['host'] = hostname

                    # Set target (hostname or full URL) using set_option
                    if hasattr(module_instance, 'target'):
                        module_instance.set_option('target', hostname)
                    elif hasattr(module_instance, 'rhost'):
                        module_instance.set_option('rhost', hostname)
                    elif hasattr(module_instance, 'rhosts'):
                        module_instance.set_option('rhosts', hostname)

                    # Set port
                    if hasattr(module_instance, 'port'):
                        module_instance.set_option('port', port)
                    elif hasattr(module_instance, 'rport'):
                        module_instance.set_option('rport', port)

                    # Set SSL based on scheme
                    if hasattr(module_instance, 'ssl'):
                        module_instance.set_option('ssl', (scheme == 'https'))

                    # Set path if specified
                    if target_info.get('path') and hasattr(module_instance, 'path'):
                        module_instance.set_option('path', target_info['path'])

                    execution = ModuleExecutor.execute(
                        self.framework,
                        ModuleExecutionRequest(
                            module=module_instance,
                            use_runtime_kernel=False,
                            use_exploit_wrapper=False,
                            collect_metrics=False,
                            skip_scope_confirm=True,
                        ),
                    )
                    if execution.blocked:
                        result["status"] = "blocked"
                        result["message"] = execution.error or "Module execution blocked"
                        return result
                    if execution.error and not execution.command_success:
                        raise RuntimeError(execution.error)
                    # Merge dict returns (common for OSINT/aux) into dynamic details.
                    run_return = execution.result
                    schema_evidence = getattr(execution, "schema_evidence", None)
                    if schema_evidence:
                        result["schema_evidence"] = list(schema_evidence)
                    schema_finding = getattr(execution, "schema_finding", None)
                    if schema_finding:
                        result["schema_finding"] = dict(schema_finding)
                    if getattr(execution, "evidence", None):
                        result["raw_evidence"] = execution.evidence

                    # Get info from __info__ (static) and vulnerability_info (dynamic)
                    module_info = getattr(module_instance, '__info__', {})
                    dynamic_info = getattr(module_instance, 'vulnerability_info', {}) or {}
                    if not isinstance(dynamic_info, dict):
                        dynamic_info = {}

                    # Prefer ModuleResult.success (scanner True = finding)
                    if hasattr(run_return, "success") and not isinstance(run_return, dict):
                        result["vulnerable"] = bool(getattr(run_return, "success"))
                        nested = getattr(run_return, "data", None)
                        if isinstance(nested, dict):
                            for k, v in nested.items():
                                if k in ("reason", "version", "severity", "client"):
                                    continue
                                dynamic_info.setdefault(k, v)
                    elif isinstance(run_return, dict):
                        for k, v in run_return.items():
                            if k in ('reason', 'version', 'severity', 'client'):
                                continue
                            dynamic_info.setdefault(k, v)
                        result['vulnerable'] = bool(run_return.get('vulnerable') or run_return.get('vuln') or run_return.get('success'))
                    elif isinstance(run_return, bool):
                        result['vulnerable'] = run_return
                    else:
                        result['vulnerable'] = bool(run_return)

                    # Soft-404 / SPA catch-all: path hit mirrored the index page.
                    if result.get("vulnerable"):
                        try:
                            from lib.scanner.http.soft_404 import finding_looks_like_index_clone

                            dyn_for_soft404 = getattr(module_instance, "vulnerability_info", {}) or {}
                            if finding_looks_like_index_clone(module_instance, dyn_for_soft404):
                                result["vulnerable"] = False
                                result["status"] = "safe"
                                result["message"] = "suppressed soft-404 (same as index)"
                                result["suppressed_soft404"] = True
                        except Exception:
                            pass

                    result['status'] = 'vulnerable' if result['vulnerable'] else 'safe'
                    session_token = (
                        str(getattr(execution, "session_id", None) or "").strip()
                        or str(dynamic_info.get("session_id") or "").strip()
                    )
                    if session_token:
                        result["session_id"] = session_token
                        dynamic_info.setdefault("session_id", session_token)

                    # Reason: prefer structured report_finding(); avoid static module blurb.
                    reason = dynamic_info.get("reason")
                    module_description = str(module_info.get("description") or "").strip()
                    report = None
                    if result.get("vulnerable") and not result.get("suppressed_soft404"):
                        try:
                            from core.scanner.finding_report import (
                                evidence_preview_from_report,
                                extract_finding_report,
                            )

                            report = extract_finding_report(dynamic_info)
                        except Exception:
                            report = None

                    if report:
                        result["report"] = report
                        result["finding"] = report.get("finding")
                        result["impact"] = report.get("impact") or {}
                        result["remediation"] = report.get("remediation") or {}
                        if report.get("severity"):
                            result["severity"] = report.get("severity")
                        result["message"] = str(report.get("finding") or reason or "")
                        preview = evidence_preview_from_report(report)
                        if preview:
                            result["evidence"] = preview
                        if isinstance(report.get("evidence"), dict):
                            result["report_evidence"] = dict(report["evidence"])
                    elif result.get("suppressed_soft404"):
                        pass  # keep soft-404 suppression message
                    elif reason:
                        result["message"] = reason
                    elif result.get("vulnerable"):
                        label = str(module_info.get("name") or module_path).strip()
                        version = dynamic_info.get("version")
                        if version:
                            result["message"] = f"{label} confirmed (version={version})"
                        else:
                            result["message"] = f"{label} confirmed"
                    else:
                        result["message"] = module_description
                    result["module_description"] = module_description

                    # Severity: structured report > dynamic > __info__
                    if not result.get("severity"):
                        result["severity"] = dynamic_info.get("severity") or module_info.get("severity")

                    if module_info.get('cve'):
                        result['cve'] = module_info.get('cve')

                    # Version and other dynamic details
                    if dynamic_info.get('version'):
                        result['version'] = dynamic_info['version']

                    # Associated exploit/auxiliary module (from __info__)
                    if module_info.get('module'):
                        result['exploit_module'] = module_info['module']

                    # Chained follow-up modules (e.g. admin_panel_detect -> bruteforce); used by agent.
                    raw_linked = module_info.get('modules') or []
                    if isinstance(raw_linked, (list, tuple)):
                        linked = []
                        seen = set()
                        for item in raw_linked:
                            if not isinstance(item, str):
                                continue
                            cleaned = item.strip()
                            if not cleaned or cleaned in seen:
                                continue
                            if not cleaned.startswith((
                                'scanner/', 'auxiliary/scanner/', 'exploit/', 'exploits/',
                            )):
                                continue
                            seen.add(cleaned)
                            linked.append(cleaned)
                        if linked:
                            result['linked_modules'] = linked

                    # Other dynamic details (excluding structured report fields)
                    result['details'] = {
                        k: v for k, v in dynamic_info.items()
                        if k not in [
                            'reason', 'version', 'severity', 'report', 'finding',
                            'evidence', 'impact', 'remediation',
                        ]
                    }
                    enrich_scanner_result(result, target_info, port=port)

                    # Prefer structured finding title / evidence preview after enrich.
                    if result.get("finding"):
                        result["module"] = result["finding"]
                    if result.get("report"):
                        try:
                            from core.scanner.finding_report import evidence_preview_from_report

                            preview = evidence_preview_from_report(result["report"])
                            if preview:
                                result["evidence"] = preview
                        except Exception:
                            pass

                    if capture_evidence and result.get("vulnerable"):
                        try:
                            from core.scanner.evidence_capture import (
                                collect_module_evidence,
                                evidence_preview,
                                write_evidence_records,
                            )

                            records = collect_module_evidence(
                                module=module_instance,
                                module_path=module_path,
                                result=result,
                                workspace=evidence_workspace,
                                existing_schema=result.get("schema_evidence"),
                            )
                            if records:
                                result["schema_evidence"] = records
                                preview = evidence_preview(records)
                                if preview:
                                    # Keep short table evidence, but prefer HTTP preview.
                                    result["evidence"] = preview
                                if evidence_dir:
                                    paths = write_evidence_records(
                                        records,
                                        directory=evidence_dir,
                                        module_path=module_path,
                                    )
                                    if paths:
                                        result["evidence_paths"] = paths
                        except Exception:
                            pass
                finally:
                    set_thread_output_quiet(False)

            except Exception as e:
                if is_soft_probe_failure(e):
                    result['status'] = 'skipped'
                    result['message'] = f"probe skipped: {e}"
                else:
                    result['message'] = f"Error: {str(e)}"
                    if verbose:
                        print_error(f"  [!] Error in {module_path}: {e}")
            
            return result
        
        # Execute modules with thread pool
        total = len(modules)
        done = 0
        found = 0
        lock = threading.Lock()
        print_info(f"Executing {total} module(s) with {threads} thread(s)...")
        exec_t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_module = {
                executor.submit(copy_context().run, execute_module, module): module
                for module in modules
            }
            
            for future in as_completed(future_to_module):
                result = future.result()
                results.append(result)
                with lock:
                    done += 1
                    current = done
                    if result.get("vulnerable"):
                        found += 1
                    findings = found
                if verbose:
                    end_progress()
                    status_icon = "[+]" if result['vulnerable'] else "[-]"
                    print_info(f"{status_icon} {result['module']}: {result['message']}")
                else:
                    # Update in-place (~every module); bar overwrites previous line
                    if current == 1 or current == total or current % 5 == 0:
                        print_progress(
                            current,
                            total,
                            label="Scanning",
                            extra=f"{findings} finding(s)",
                        )

        end_progress()
        print_info(
            f"Module execution finished in {self._format_duration(time.perf_counter() - exec_t0)}"
        )
        return results
    
    def _display_results(
        self,
        results: List[Dict],
        raw_results: List[Dict],
        verbose: bool,
        grouped: bool = True,
        timing: Optional[Dict[str, float]] = None,
        target_info: Optional[Dict[str, Any]] = None,
    ):
        """Display scan results as a numbered table (for `use <n>`)."""
        print_empty()
        print_info("=" * 70)
        print_success("Scanner Results")
        print_info("=" * 70)
        print_empty()

        total = len(raw_results)
        raw_vulnerable = sum(1 for r in raw_results if r.get("vulnerable"))
        unique_vulnerable = sum(1 for r in results if r.get("vulnerable"))
        safe = sum(
            1
            for r in raw_results
            if not r.get("vulnerable") and r.get("status") not in ("error",)
        )
        skipped = sum(1 for r in raw_results if r.get("status") == "skipped")
        errors = sum(1 for r in raw_results if r.get("status") == "error")

        print_info(f"Total modules executed: {total}")
        if grouped and raw_vulnerable != unique_vulnerable:
            print_success(
                f"Vulnerabilities found: {unique_vulnerable} unique "
                f"({raw_vulnerable} detections before deduplication)"
            )
        else:
            print_success(f"Vulnerabilities found: {unique_vulnerable}")
        print_info(f"Safe: {safe}")
        if skipped > 0:
            print_info(f"Skipped: {skipped}")
        if errors > 0:
            print_warning(f"Errors: {errors}")
        if timing:
            print_empty()
            print_info("Timing:")
            if "stack_gate" in timing:
                print_info(f"  Stack gate: {self._format_duration(timing['stack_gate'])}")
            if "prefetch" in timing:
                print_info(f"  Prefetch:  {self._format_duration(timing['prefetch'])}")
            if "execute" in timing:
                print_info(f"  Execute:   {self._format_duration(timing['execute'])}")
            if "total" in timing:
                print_info(f"  Total:     {self._format_duration(timing['total'])}")
        print_empty()

        entries = self._build_finding_entries(
            results,
            grouped=grouped,
            target_info=target_info or {},
        )
        # Persist for `use <n>`
        try:
            self.framework.last_scanner_findings = entries
        except Exception:
            pass

        if entries:
            print_success("FINDINGS:")
            headers = ["#", "Sev", "Finding", "Host", "Service", "Scanner", "Module", "Evidence"]
            rows = []
            for entry in entries:
                def _cell(value, fallback="-"):
                    text = " ".join(str(value or fallback).split())
                    return text or fallback

                rows.append(
                    [
                        str(entry["index"]),
                        self._format_severity(entry.get("severity")) or "-",
                        _cell(entry.get("title"), ""),
                        _cell(entry.get("host")),
                        _cell(entry.get("service")),
                        _cell(entry.get("scanner_label") or entry.get("scanner_path")),
                        _cell(entry.get("module_label")),
                        _cell(entry.get("evidence")),
                    ]
                )
            print_table(
                headers,
                rows,
                expand_to_terminal=True,
                prefer_single_line=True,
                expand_headers=("Evidence",),
                # Wrap instead of truncating — never ellipsize cell content.
                wrap_extra_headers=(
                    "Finding",
                    "Host",
                    "Service",
                    "Scanner",
                    "Module",
                    "Evidence",
                ),
                column_min_widths={
                    "#": 1,
                    "Sev": 8,
                    "Finding": 12,
                    "Host": 10,
                    "Service": 9,
                    "Scanner": 12,
                    "Module": 10,
                },
            )
            print_empty()
            print_info(
                "Select a finding:  use <n>   "
                "(loads Module/exploit-auxiliary if linked, else Scanner)"
            )
            usable = sum(1 for e in entries if e.get("module_path"))
            if usable:
                print_info(f"{usable}/{len(entries)} finding(s) have a loadable module path")
            print_empty()
        else:
            try:
                self.framework.last_scanner_findings = []
            except Exception:
                pass

        if verbose:
            safe_results = [
                r
                for r in raw_results
                if not r.get("vulnerable") and r.get("status") != "error"
            ]
            if safe_results:
                print_info("SAFE (No vulnerabilities detected):")
                print_info("-" * 70)
                for result in safe_results:
                    print_status(f"{result['module']}: {result['message']}")
                print_empty()

        error_results = [r for r in raw_results if r.get("status") == "error"]
        if error_results:
            print_warning("ERRORS:")
            print_info("-" * 70)
            for result in error_results:
                print_warning(f"{result['module']}: {result['message']}")
            print_empty()

        print_info("=" * 70)

    @staticmethod
    def _clip(text: str, width: int) -> str:
        text = " ".join(str(text or "").split())
        if width <= 3 or len(text) <= width:
            return text
        return text[: width - 3] + "..."

    @staticmethod
    def _normalize_cve(value: Any) -> str:
        text = str(value or "").strip().upper()
        match = _CVE_RE.search(text)
        if not match:
            return ""
        return f"CVE-{match.group(1)}-{match.group(2)}"

    @staticmethod
    def _is_followup_path(path: str) -> bool:
        """True for actionable follow-ups (exploit/auxiliary), not scanner detects."""
        cleaned = str(path or "").strip()
        if not cleaned or cleaned.startswith("scanner/"):
            return False
        return cleaned.startswith(_FOLLOWUP_PREFIXES)

    @staticmethod
    def _module_kind_for_path(path: str) -> str:
        cleaned = str(path or "").strip().lower()
        if cleaned.startswith(("exploit/", "exploits/")):
            return "exploit"
        if cleaned.startswith("auxiliary/"):
            return "auxiliary"
        if cleaned.startswith("scanner/"):
            return "scanner"
        return "module"

    def _all_followup_paths(self) -> List[str]:
        cached = getattr(self, "_followup_paths_cache", None)
        if cached is not None:
            return cached
        paths: List[str] = []
        try:
            discovered = self.framework.module_loader.discover_modules() or {}
            paths = sorted(
                p for p in discovered.keys() if self._is_followup_path(p)
            )
        except Exception:
            paths = []
        self._followup_paths_cache = paths
        return paths

    def _followups_for_cve(self, cve: str) -> List[str]:
        """Resolve exploit/auxiliary module paths for a CVE (DB + path heuristics)."""
        normalized = self._normalize_cve(cve)
        if not normalized:
            return []

        cache = getattr(self, "_followups_by_cve_cache", None)
        if cache is None:
            cache = {}
            self._followups_by_cve_cache = cache
        if normalized in cache:
            return list(cache[normalized])

        found: List[str] = []
        seen: Set[str] = set()

        def _add(path: Any) -> None:
            cleaned = str(path or "").strip()
            if not cleaned or cleaned in seen or not self._is_followup_path(cleaned):
                return
            seen.add(cleaned)
            found.append(cleaned)

        try:
            rows = self.framework.module_loader.search_modules_db(
                cve=normalized,
                limit=50,
            ) or []
            for row in rows:
                if isinstance(row, dict):
                    _add(row.get("path"))
        except Exception:
            pass

        year, num = normalized.split("-")[1], normalized.split("-")[2]
        tokens = (
            f"cve_{year}_{num}",
            f"cve-{year}-{num}",
            f"{year}_{num}",
        )
        for path in self._all_followup_paths():
            low = path.lower()
            if any(token in low for token in tokens):
                _add(path)

        # Prefer exploits before auxiliary when both match the same CVE.
        found.sort(
            key=lambda p: (
                0 if p.startswith(("exploit/", "exploits/")) else 1,
                p,
            )
        )
        cache[normalized] = list(found)
        return list(found)

    def _collect_followup_modules(self, *sources: Any) -> List[str]:
        """Collect linked exploit/auxiliary paths from result dicts / groups."""
        found: List[str] = []
        seen: Set[str] = set()

        def _add(path: Any) -> None:
            cleaned = str(path or "").strip()
            if not cleaned or cleaned in seen or not self._is_followup_path(cleaned):
                return
            seen.add(cleaned)
            found.append(cleaned)

        for source in sources:
            if source is None:
                continue
            if isinstance(source, dict):
                items = [source]
            elif isinstance(source, (list, tuple)):
                items = list(source)
            else:
                items = []

            for item in items:
                if not isinstance(item, dict):
                    continue
                _add(item.get("exploit_module"))
                linked = item.get("linked_modules") or []
                if isinstance(linked, str):
                    linked = [linked]
                if isinstance(linked, (list, tuple)):
                    for entry in linked:
                        _add(entry)
                cve = self._normalize_cve(item.get("cve"))
                if cve:
                    for path in self._followups_for_cve(cve):
                        _add(path)
        return found

    def _build_finding_entries(
        self,
        results: List[Dict],
        *,
        grouped: bool,
        target_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Build numbered finding rows for display + `use <n>`."""
        entries: List[Dict[str, Any]] = []
        default_host = str(target_info.get("hostname") or "")
        default_port = target_info.get("port")
        default_scheme = str(target_info.get("scheme") or "")

        def _port_from_service(service: str) -> Optional[int]:
            if not service or ":" not in service:
                return None
            try:
                return int(service.rsplit(":", 1)[-1])
            except ValueError:
                return None

        def _label(modules: List[str]) -> str:
            if not modules:
                return "-"
            if len(modules) == 1:
                return modules[0]
            return f"{modules[0]} (+{len(modules) - 1})"

        if grouped:
            for group in group_scanner_results(results):
                rep = group.representative or {}
                module_paths = list(group.module_paths or [])
                scanner_path = module_paths[0] if module_paths else str(rep.get("path") or "").strip()
                scanner_paths = [p for p in module_paths if str(p or "").strip()] or (
                    [scanner_path] if scanner_path else []
                )
                followups = self._collect_followup_modules(rep, list(group.members or []))
                if group.cve:
                    for path in self._followups_for_cve(group.cve):
                        if path not in followups:
                            followups.append(path)
                followup = followups[0] if followups else ""
                # use <n>: prefer linked follow-up, fall back to scanner detection module
                module_path = followup or scanner_path
                kind = self._module_kind_for_path(module_path) if module_path else ""
                host = (group.hosts[0] if group.hosts else "") or default_host
                service = (group.services[0] if group.services else "") or ""
                port = _port_from_service(service) or rep.get("port") or default_port
                scheme = str(rep.get("scheme") or default_scheme or "")
                evidence = ""
                if group.evidence:
                    evidence = group.evidence[0]
                    if len(group.evidence) > 1:
                        evidence = f"{evidence} (+{len(group.evidence) - 1})"
                else:
                    evidence = str(rep.get("evidence") or rep.get("message") or "")
                title = (
                    str(rep.get("finding") or "").strip()
                    or str(group.title or "").strip()
                    or str(rep.get("module") or scanner_path or "Finding").strip()
                )
                if group.cve and group.cve not in title:
                    title = f"[{group.cve}] {title}"
                schema_evidence: List[Dict[str, Any]] = []
                evidence_paths: List[str] = []
                report = None
                if isinstance(rep.get("report"), dict):
                    report = dict(rep["report"])
                for member in list(group.members or []) or [rep]:
                    if not isinstance(member, dict):
                        continue
                    for item in member.get("schema_evidence") or []:
                        if isinstance(item, dict):
                            schema_evidence.append(item)
                    for path in member.get("evidence_paths") or []:
                        text = str(path or "").strip()
                        if text and text not in evidence_paths:
                            evidence_paths.append(text)
                    if report is None and isinstance(member.get("report"), dict):
                        report = dict(member["report"])
                entry = {
                        "index": len(entries) + 1,
                        "title": title,
                        "severity": group.severity or rep.get("severity") or "",
                        "cve": group.cve or "",
                        "host": host,
                        "service": service,
                        "port": port,
                        "scheme": scheme,
                        "evidence": evidence,
                        "module_path": module_path,
                        "scanner_path": scanner_path,
                        "scanner_label": _label(scanner_paths),
                        "exploit_module": followup if followup.startswith(("exploit/", "exploits/")) else "",
                        "followup_modules": followups,
                        "exploit_modules": followups,  # back-compat for use_command
                        "module_kind": kind,
                        "module_label": _label(followups),
                        "occurrences": group.occurrences,
                        "schema_evidence": schema_evidence,
                        "evidence_paths": evidence_paths,
                    }
                if report:
                    entry["report"] = report
                    entry["finding"] = report.get("finding") or title
                    entry["impact"] = report.get("impact") or {}
                    entry["remediation"] = report.get("remediation") or {}
                    if isinstance(report.get("evidence"), dict):
                        entry["report_evidence"] = dict(report["evidence"])
                entries.append(entry)
        else:
            for result in results:
                if not result.get("vulnerable"):
                    continue
                scanner_path = str(result.get("path") or "").strip()
                followups = self._collect_followup_modules(result)
                followup = followups[0] if followups else ""
                module_path = followup or scanner_path
                kind = self._module_kind_for_path(module_path) if module_path else ""
                host = str(result.get("host") or default_host or "")
                service = str(result.get("service") or "")
                port = result.get("port") or _port_from_service(service) or default_port
                scheme = str(result.get("scheme") or default_scheme or "")
                evidence = str(result.get("evidence") or result.get("message") or "")
                title = (
                    str(result.get("finding") or "").strip()
                    or str(result.get("module") or scanner_path or "Finding").lstrip("[+]").strip()
                )
                cve = str(result.get("cve") or "")
                if cve and cve not in title:
                    title = f"[{cve}] {title}"
                schema_evidence = [
                    item
                    for item in (result.get("schema_evidence") or [])
                    if isinstance(item, dict)
                ]
                evidence_paths = [
                    str(p).strip()
                    for p in (result.get("evidence_paths") or [])
                    if str(p or "").strip()
                ]
                entry = {
                        "index": len(entries) + 1,
                        "title": title,
                        "severity": result.get("severity") or "",
                        "cve": cve,
                        "host": host,
                        "service": service,
                        "port": port,
                        "scheme": scheme,
                        "evidence": evidence,
                        "module_path": module_path,
                        "scanner_path": scanner_path,
                        "scanner_label": scanner_path or "-",
                        "exploit_module": followup if followup.startswith(("exploit/", "exploits/")) else "",
                        "followup_modules": followups,
                        "exploit_modules": followups,
                        "module_kind": kind,
                        "module_label": _label(followups),
                        "occurrences": int(result.get("duplicate_count") or 1),
                        "schema_evidence": schema_evidence,
                        "evidence_paths": evidence_paths,
                    }
                if isinstance(result.get("report"), dict):
                    entry["report"] = dict(result["report"])
                    entry["finding"] = result.get("finding") or title
                    entry["impact"] = result.get("impact") or {}
                    entry["remediation"] = result.get("remediation") or {}
                    if isinstance(result.get("report_evidence"), dict):
                        entry["report_evidence"] = dict(result["report_evidence"])
                    elif isinstance(result["report"].get("evidence"), dict):
                        entry["report_evidence"] = dict(result["report"]["evidence"])
                entries.append(entry)
        return entries

    def _persist_findings_to_workspace(self, entries: List[Dict[str, Any]]) -> None:
        """Auto-save numbered scanner findings into the active workspace DB."""
        if not entries:
            return
        try:
            from core.workspace_intel import WorkspaceIntelStore

            stats = WorkspaceIntelStore(self.framework).record_scanner_findings(
                entries,
                source="scanner",
            )
        except Exception as exc:
            print_warning(f"Could not save findings to workspace DB: {exc}")
            return

        saved = int(stats.get("saved") or 0)
        updated = int(stats.get("updated") or 0)
        failed = int(stats.get("failed") or 0)
        evidence = int(stats.get("evidence") or 0)
        if saved or updated:
            print_success(
                f"Workspace DB: {saved} new finding(s) saved"
                + (f", {updated} updated" if updated else "")
            )
            if evidence:
                print_info(f"Workspace DB: {evidence} evidence loot item(s) saved")
            print_info("View with: vuln --list  (alias: vulns --list)")
        elif failed:
            print_warning(f"Workspace DB: failed to save {failed} finding(s)")
        else:
            print_info("Workspace DB: no new findings to save")
            if evidence:
                print_info(f"Workspace DB: {evidence} evidence loot item(s) saved")

    def _print_vulnerable_result(self, result: Dict[str, Any]):
        # Kept for callers/tests; primary UI is the numbered table.
        module_name = str(result.get("module", "")).lstrip("[+]").strip()
        print_success(module_name)
        if result.get("host") or result.get("service"):
            host = result.get("host") or "unknown"
            service = result.get("service") or "unknown"
            print_info(f"    Target: {host} ({service})")
        message = str(result.get("message") or "").strip()
        evidence = str(result.get("evidence") or "").strip()
        if evidence:
            print_info(f"    Evidence: {evidence}")
        elif message:
            print_info(f"    Evidence: {message}")
        if result.get("cve"):
            print_info(f"    CVE: {result['cve']}")
        if result.get("severity"):
            print_info(f"    Severity: {self._format_severity(result['severity'])}")
        if result.get("exploit_module"):
            print_success(f"Exploit module: {result['exploit_module']}")

    def _print_finding_group(self, group):
        title = group.title
        if group.cve:
            print_success(f"[{group.cve}] {title}")
        else:
            print_success(title)
        if group.severity:
            print_info(f"    Severity: {self._format_severity(group.severity)}")
        if group.hosts:
            print_info(f"    Hosts: {', '.join(group.hosts)}")
        if group.services:
            print_info(f"    Services: {', '.join(group.services)}")
        if group.module_paths:
            print_info(f"    Modules: {', '.join(group.module_paths)}")
    
    def _auto_exploit(self, results: List[Dict], target_info: Dict[str, Any]):
        """Automatically launch exploit modules for detected vulnerabilities"""
        vulnerable_results = [r for r in results if r['vulnerable'] and 'exploit_module' in r]
        
        if not vulnerable_results:
            return
        
        print_empty()
        print_info("=" * 70)
        print_success("Auto-exploit: Launching exploit modules...")
        print_info("=" * 70)
        print_empty()
        
        for result in vulnerable_results:
            exploit_path = result['exploit_module']
            print_status(f"Launching exploit: {exploit_path}")
            
            try:
                # Load exploit module
                exploit_instance = self.framework.module_loader.load_module(
                    exploit_path,
                    load_only=False,
                    framework=self.framework
                )
                
                if not exploit_instance:
                    print_warning(f"Failed to load module: {exploit_path}")
                    continue
                
                # Set target options from target_info
                hostname = target_info['hostname']
                port = target_info['port']
                
                # Set target
                if hasattr(exploit_instance, 'target'):
                    exploit_instance.set_option('target', hostname)
                elif hasattr(exploit_instance, 'rhost'):
                    exploit_instance.set_option('rhost', hostname)
                elif hasattr(exploit_instance, 'rhosts'):
                    exploit_instance.set_option('rhosts', hostname)
                
                # Set port
                if hasattr(exploit_instance, 'port'):
                    exploit_instance.set_option('port', port)
                elif hasattr(exploit_instance, 'rport'):
                    exploit_instance.set_option('rport', port)
                
                # Set SSL if needed
                if hasattr(exploit_instance, 'ssl'):
                    exploit_instance.set_option('ssl', (target_info['scheme'] == 'https'))
                
                # Set as current module and execute exploit
                self.framework.current_module = exploit_instance
                print_status(f"Executing exploit against {hostname}:{port}...")
                success = self.framework.execute_module()
                
                if success:
                    print_success(f"Exploit succeeded: {exploit_path}")
                else:
                    print_warning(f"Exploit failed: {exploit_path}")
                
            except Exception as e:
                print_warning(f"Error launching {exploit_path}: {e}")
                import traceback
                traceback.print_exc()
        
        print_empty()
        print_info("=" * 70)
    
    def _list_modules(self) -> bool:
        """List all available scanner modules"""
        modules = self._discover_modules()
        
        if not modules:
            print_warning("No scanner modules found")
            return False
        
        print_info(f"Available scanner modules ({len(modules)}):")
        print_empty()
        
        # Group by category
        categories = {}
        for module in modules:
            path_parts = module['path'].split('/')
            if len(path_parts) > 1:
                category = path_parts[1]  # e.g., 'http'
            else:
                category = 'other'
            
            if category not in categories:
                categories[category] = []
            categories[category].append(module)
        
        for category in sorted(categories.keys()):
            print_info(f"  {category.upper()}/")
            for module in categories[category]:
                print_info(f"    {module['path']}")
                print_info(f"      Name: {module['name']}")
                if module['description']:
                    print_info(f"      Description: {module['description']}")
                print_empty()
        
        return True
