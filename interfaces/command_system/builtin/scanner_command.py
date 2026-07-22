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
    set_thread_output_quiet,
    color_red,
    color_yellow,
    color_blue,
    color_green,
)
from urllib.parse import urlparse
import threading
import socket
from contextvars import copy_context
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set, Optional, Tuple
import errno

from core.scanner.result_dedup import (
    deduplicate_scanner_results,
    enrich_scanner_result,
    group_scanner_results,
    reason_redundant_with_evidence,
)
from core.scanner.probe_failure import is_soft_probe_failure
from core.framework.module_executor import ModuleExecutionRequest, ModuleExecutor


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
        return "scanner -u <URL|HOSTNAME:PORT> [--protocol PROTO] [--tags TAG1,TAG2] [--port PORT] [--threads N] [--module MODULE] [--scan-ports] [--auto-exploit]"
    
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
    --threads N          Number of concurrent threads (default: 5)
    --module MODULE      Execute only a specific module (e.g., http/apache_version_check)
    --list               List all available scanner modules
    --verbose, -v        Show detailed output for each module
    --no-cache           Disable HTTP request caching
    --no-dedup           Disable grouping/deduplication of identical findings

Examples:
    scanner -u https://example.com
    scanner -u http://192.168.1.100 --threads 10
    scanner -u https://example.com --module http/apache_version_check
    scanner -u example.com --protocol http
    scanner -u example.com --tags ssh --port 2222
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
            
            # Discover scanner modules
            modules = self._discover_modules()
            
            if not modules:
                print_warning("No scanner modules found")
                return False
            
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
            
            print_empty()
            
            # Execute modules
            raw_results = self._execute_modules(modules, target_info, options['threads'], options['verbose'])
            if options.get('no_dedup'):
                results = raw_results
            else:
                results = deduplicate_scanner_results(raw_results, target_info=target_info)
            
            # Display results
            self._display_results(results, raw_results, options['verbose'], grouped=not options.get('no_dedup'))
            
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
            'threads': 5,
            'module': None,
            'list': False,
            'verbose': False,
            'no_cache': False,
            'no_dedup': False,
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
        """Discover all scanner modules"""
        modules = []
        
        try:
            discovered = self.framework.module_loader.discover_modules()
            
            for module_path, file_path in discovered.items():
                if module_path.startswith('scanner/'):
                    try:
                        # Get module info without loading
                        module_info = self.framework.module_loader.get_module_info(module_path)
                        modules.append({
                            'path': module_path,
                            'file_path': file_path,
                            'name': module_info.get('name', module_path),
                            'description': module_info.get('description', ''),
                            'author': module_info.get('author', ''),
                            'tags': module_info.get('tags', [])
                        })
                    except Exception as e:
                        # Skip modules that can't be loaded
                        continue
        except Exception as e:
            print_error(f"Error discovering modules: {e}")
        
        return sorted(modules, key=lambda x: x['path'])
    
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

    def _execute_modules(self, modules: List[Dict], target_info: Dict[str, Any], threads: int, verbose: bool) -> List[Dict]:
        """Execute scanner modules against target"""
        results = []
        
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
                    # Load module
                    module_instance = self.framework.module_loader.load_module(
                        module_path,
                        load_only=False,
                        framework=self.framework,
                    )

                    if not module_instance:
                        result['message'] = 'Failed to load module'
                        return result

                    # Set target options
                    hostname = target_info['hostname']
                    port = self._choose_port_for_module(module_path, target_info)
                    scheme = 'https' if port == 443 else 'http'
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
                            collect_metrics=True,
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

                    if isinstance(run_return, dict):
                        for k, v in run_return.items():
                            if k in ('reason', 'version', 'severity', 'client'):
                                continue
                            dynamic_info.setdefault(k, v)
                    else:
                        # ModuleResult / other objects: surface nested data + session_id.
                        nested = getattr(run_return, "data", None)
                        if isinstance(nested, dict):
                            for k, v in nested.items():
                                if k in ('reason', 'version', 'severity', 'client'):
                                    continue
                                dynamic_info.setdefault(k, v)
                        nested_session = (
                            getattr(run_return, "session_id", None)
                            or getattr(execution, "session_id", None)
                        )
                        if nested_session and not dynamic_info.get("session_id"):
                            dynamic_info["session_id"] = str(nested_session)

                    if isinstance(run_return, bool):
                        result['vulnerable'] = run_return
                    elif isinstance(run_return, dict):
                        result['vulnerable'] = bool(run_return.get('vulnerable') or run_return.get('vuln'))
                    else:
                        result['vulnerable'] = bool(run_return)
                    result['status'] = 'vulnerable' if result['vulnerable'] else 'safe'
                    session_token = (
                        str(getattr(execution, "session_id", None) or "").strip()
                        or str(dynamic_info.get("session_id") or "").strip()
                    )
                    if session_token:
                        result["session_id"] = session_token
                        dynamic_info.setdefault("session_id", session_token)

                    # Reason: dynamic finding text; avoid static module description as output.
                    reason = dynamic_info.get("reason")
                    module_description = str(module_info.get("description") or "").strip()
                    if reason:
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

                    # Severity: from __info__ or dynamic (for detection/vuln level)
                    result['severity'] = dynamic_info.get('severity') or module_info.get('severity')

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

                    # Other dynamic details (excluding reason, version, severity)
                    result['details'] = {
                        k: v for k, v in dynamic_info.items()
                        if k not in ['reason', 'version', 'severity']
                    }
                    enrich_scanner_result(result, target_info, port=port)
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
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_module = {
                executor.submit(copy_context().run, execute_module, module): module
                for module in modules
            }
            
            for future in as_completed(future_to_module):
                result = future.result()
                results.append(result)
                
                if verbose:
                    status_icon = "[+]" if result['vulnerable'] else "[-]"
                    print_info(f"{status_icon} {result['module']}: {result['message']}")
        
        return results
    
    def _display_results(
        self,
        results: List[Dict],
        raw_results: List[Dict],
        verbose: bool,
        grouped: bool = True,
    ):
        """Display scan results, optionally grouped by vulnerability/host/service/evidence."""
        print_empty()
        print_info("=" * 70)
        print_success("Scanner Results")
        print_info("=" * 70)
        print_empty()
        
        # Count statistics
        total = len(raw_results)
        raw_vulnerable = sum(1 for r in raw_results if r.get('vulnerable'))
        unique_vulnerable = sum(1 for r in results if r.get('vulnerable'))
        safe = sum(
            1 for r in raw_results
            if not r.get('vulnerable') and r.get('status') not in ('error',)
        )
        skipped = sum(1 for r in raw_results if r.get('status') == 'skipped')
        errors = sum(1 for r in raw_results if r.get('status') == 'error')
        
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
        print_empty()
        
        vulnerable_results = [r for r in results if r.get('vulnerable')]
        if vulnerable_results and grouped:
            finding_groups = group_scanner_results(results)
            print_success("VULNERABILITIES DETECTED (grouped by host/service/evidence):")
            print_info("-" * 70)
            for group in finding_groups:
                self._print_finding_group(group)
                print_info("-" * 30)
        elif vulnerable_results:
            print_success("VULNERABILITIES DETECTED:")
            print_info("-" * 70)
            for result in vulnerable_results:
                self._print_vulnerable_result(result)
                print_info("-" * 30)

        
        # Show safe results if verbose
        if verbose:
            safe_results = [r for r in raw_results if not r.get('vulnerable') and r.get('status') != 'error']
            if safe_results:
                print_info("SAFE (No vulnerabilities detected):")
                print_info("-" * 70)
                for result in safe_results:
                    print_status(f"{result['module']}: {result['message']}")
                print_empty()
        
        # Show errors if any
        error_results = [r for r in raw_results if r.get('status') == 'error']
        if error_results:
            print_warning("ERRORS:")
            print_info("-" * 70)
            for result in error_results:
                print_warning(f"{result['module']}: {result['message']}")
            print_empty()
        
        print_info("=" * 70)

    def _print_vulnerable_result(self, result: Dict[str, Any]):
        module_name = str(result.get('module', '')).lstrip('[+]').strip()
        print_success(module_name)
        if result.get('host') or result.get('service'):
            host = result.get('host') or 'unknown'
            service = result.get('service') or 'unknown'
            print_info(f"    Target: {host} ({service})")
        print_info(f"    Path: {result.get('path', '')}")
        message = str(result.get("message") or "").strip()
        evidence = str(result.get("evidence") or "").strip()
        if evidence:
            print_info(f"    Evidence: {evidence}")
        elif message:
            print_info(f"    Evidence: {message}")
        if message and not reason_redundant_with_evidence(message, evidence or message):
            print_info(f"    Reason: {message}")
        if 'version' in result:
            print_info(f"    Version: {result['version']}")
        if result.get('cve'):
            print_info(f"    CVE: {result['cve']}")
        if result.get('severity'):
            print_info(f"    Severity: {self._format_severity(result['severity'])}")
        duplicate_count = int(result.get('duplicate_count') or 1)
        if duplicate_count > 1:
            sources = result.get('dedup_sources') or []
            print_info(f"    Occurrences: {duplicate_count}")
            if sources:
                print_info(f"    Sources: {', '.join(sources)}")
        details = result.get('details') or {}
        if details:
            for key, value in details.items():
                print_info(f"    {key}: {value}")
        if 'exploit_module' in result:
            print_success(f"Exploit module: {result['exploit_module']}")
            print_info(f"    Use: use {result['exploit_module']}")

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
        if group.evidence:
            preview = group.evidence[0]
            if len(group.evidence) > 1:
                preview = f"{preview} (+{len(group.evidence) - 1} variant(s))"
            print_info(f"    Evidence: {preview}")
        if group.module_paths:
            print_info(f"    Modules: {', '.join(group.module_paths)}")
        if group.occurrences > 1:
            print_info(f"    Occurrences: {group.occurrences}")
        representative = group.representative or {}
        if representative.get('exploit_module'):
            print_success(f"Exploit module: {representative['exploit_module']}")
            print_info(f"    Use: use {representative['exploit_module']}")
        rep_message = str(representative.get("message") or "").strip()
        rep_evidence = str((group.evidence or [""])[0] or representative.get("evidence") or "").strip()
        if rep_message and not reason_redundant_with_evidence(rep_message, rep_evidence):
            print_info(f"    Reason: {rep_message}")
    
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
