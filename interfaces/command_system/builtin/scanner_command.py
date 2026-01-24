#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner command implementation - Execute all scanner modules against a target URL
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table, print_empty
from urllib.parse import urlparse
import threading
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set, Optional


class ScannerCommand(BaseCommand):
    """Command to execute all scanner modules against a target URL"""
    
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

Examples:
    scanner -u https://example.com
    scanner -u http://192.168.1.100 --threads 10
    scanner -u https://example.com --module http/apache_version_check
    scanner -u example.com --protocol http
    scanner -u example.com --tags ssh --port 2222
    scanner -u example.com --scan-ports
    scanner --list
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the scanner command"""
        try:
            # Check for help flag first
            if '--help' in args or '-h' in args:
                print_info(self.help_text)
                return True
            
            # Parse arguments
            options = self._parse_args(args)
            
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
                    open_ports = self._scan_ports(target_info['hostname'], target_info.get('port'))
                    if open_ports:
                        print_info(f"Open ports detected: {', '.join(map(str, open_ports))}")
                        # Filter modules based on detected ports
                        modules = self._filter_modules_by_ports(modules, open_ports)
                        if not modules:
                            print_warning("No modules available for detected ports")
                            return False
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
            results = self._execute_modules(modules, target_info, options['threads'], options['verbose'])
            
            # Display results
            self._display_results(results, options['verbose'])
            
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
            'no_cache': False
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
                        # Determine scheme from port
                        if port == 443:
                            scheme = 'https'
                        elif port == 80:
                            scheme = 'http'
                        else:
                            scheme = 'http'  # Default
                        return {
                            'hostname': hostname,
                            'port': port,
                            'scheme': scheme,
                            'path': '/',
                            'url': f"{scheme}://{hostname}:{port}/"
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
            # FTP
            21: 'ftp', 2121: 'ftp',
            # SSH
            22: 'ssh', 2222: 'ssh',
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
        for port in ports:
            proto = self._port_to_protocol(port)
            if proto:
                protocols.add(proto)
        
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
    
    def _scan_ports(self, hostname: str, default_port: Optional[int] = None, timeout: float = 1.0) -> List[int]:
        """Scan common ports on target hostname"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 2222]
        
        # If default_port specified, prioritize it
        if default_port and default_port not in common_ports:
            common_ports.insert(0, default_port)
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((hostname, port))
                sock.close()
                return result == 0
            except:
                return False
        
        # Quick scan with threading
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, port): port for port in common_ports}
            for future in as_completed(futures):
                port = futures[future]
                if future.result():
                    open_ports.append(port)
        
        return sorted(open_ports)
    
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
                'details': {}
            }
            
            try:
                if verbose:
                    print_info(f"[*] Executing: {module_path}")
                
                # Load module
                module_instance = self.framework.module_loader.load_module(
                    module_path, 
                    load_only=False, 
                    framework=self.framework
                )
                
                if not module_instance:
                    result['message'] = 'Failed to load module'
                    return result
                
                # Set target options
                hostname = target_info['hostname']
                port = target_info['port']
                scheme = target_info['scheme']
                
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
                
                # Execute run() (returns True/False)
                result['vulnerable'] = module_instance.run()
                result['status'] = 'vulnerable' if result['vulnerable'] else 'safe'
                
                # Get info from __info__ (static) and vulnerability_info (dynamic)
                module_info = getattr(module_instance, '__info__', {})
                dynamic_info = module_instance.vulnerability_info
                
                # Reason: dynamic first, then from __info__ description
                result['message'] = dynamic_info.get('reason') or module_info.get('description', '')
                
                # Confidence: from __info__ or default
                result['confidence'] = dynamic_info.get('confidence') or module_info.get('confidence', 'high')
                
                # Version and other dynamic details
                if dynamic_info.get('version'):
                    result['version'] = dynamic_info['version']
                
                # Associated exploit/auxiliary module (from __info__)
                if module_info.get('module'):
                    result['exploit_module'] = module_info['module']
                
                # Other dynamic details (excluding reason, version, confidence)
                result['details'] = {k: v for k, v in dynamic_info.items() 
                                   if k not in ['reason', 'version', 'confidence']}
                
            except Exception as e:
                result['message'] = f"Error: {str(e)}"
                if verbose:
                    print_error(f"  [!] Error in {module_path}: {e}")
            
            return result
        
        # Execute modules with thread pool
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_module = {
                executor.submit(execute_module, module): module 
                for module in modules
            }
            
            for future in as_completed(future_to_module):
                result = future.result()
                results.append(result)
                
                if verbose:
                    status_icon = "[+]" if result['vulnerable'] else "[-]"
                    print_info(f"{status_icon} {result['module']}: {result['message']}")
        
        return results
    
    def _display_results(self, results: List[Dict], verbose: bool):
        """Display scan results"""
        print_empty()
        print_info("=" * 70)
        print_success("Scanner Results")
        print_info("=" * 70)
        print_empty()
        
        # Count statistics
        total = len(results)
        vulnerable = sum(1 for r in results if r['vulnerable'])
        safe = sum(1 for r in results if not r['vulnerable'] and r['status'] != 'error')
        errors = sum(1 for r in results if r['status'] == 'error')
        
        print_info(f"Total modules executed: {total}")
        print_success(f"Vulnerabilities found: {vulnerable}")
        print_info(f"Safe: {safe}")
        if errors > 0:
            print_warning(f"Errors: {errors}")
        print_empty()
        
        # Show vulnerable results first
        vulnerable_results = [r for r in results if r['vulnerable']]
        if vulnerable_results:
            print_success("VULNERABILITIES DETECTED:")
            print_info("-" * 70)
            for result in vulnerable_results:
                # Remove any existing [+] prefix from module name (print_success adds it automatically)
                module_name = result['module'].lstrip('[+]').strip()
                print_success(module_name)
                print_info(f"    Path: {result['path']}")
                print_info(f"    Reason: {result['message']}")
                if 'version' in result:
                    print_info(f"    Version: {result['version']}")
                if 'confidence' in result:
                    print_info(f"    Confidence: {result['confidence']}")
                if result['details']:
                    for key, value in result['details'].items():
                        print_info(f"    {key}: {value}")
                # Show associated exploit/auxiliary module
                if 'exploit_module' in result:
                    print_success(f"Exploit module: {result['exploit_module']}")
                    print_info(f"    Use: use {result['exploit_module']}")
                print_info("-" * 30)

        
        # Show safe results if verbose
        if verbose:
            safe_results = [r for r in results if not r['vulnerable'] and r['status'] != 'error']
            if safe_results:
                print_info("SAFE (No vulnerabilities detected):")
                print_info("-" * 70)
                for result in safe_results:
                    print_status(f"{result['module']}: {result['message']}")
                print_empty()
        
        # Show errors if any
        error_results = [r for r in results if r['status'] == 'error']
        if error_results:
            print_warning("ERRORS:")
            print_info("-" * 70)
            for result in error_results:
                print_warning(f"{result['module']}: {result['message']}")
            print_empty()
        
        print_info("=" * 70)
    
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
