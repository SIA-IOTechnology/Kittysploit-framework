#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network discovery command implementation
"""

import socket
import threading
import time
import ipaddress
import subprocess
import platform
import re
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class NetworkDiscoverCommand(BaseCommand):
    """Command to discover hosts on the network"""
    
    def __init__(self, framework=None, session=None, output_handler=None):
        """Initialize the command and load OUI database"""
        super().__init__(framework, session, output_handler)
        self.oui_db = None
        self._load_oui_database()
    
    def _load_oui_database(self):
        """Load OUI (MAC vendor) database"""
        try:
            # Get the path to oui.json relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            oui_path = os.path.join(current_dir, '..', '..', '..', 'data', 'vendors', 'oui.json')
            oui_path = os.path.normpath(oui_path)
            
            if os.path.exists(oui_path):
                with open(oui_path, 'r', encoding='utf-8') as f:
                    self.oui_db = json.load(f)
            else:
                print_warning(f"OUI database not found at {oui_path}")
        except Exception as e:
            print_warning(f"Failed to load OUI database: {e}")
    
    def _get_mac_vendor(self, mac_address):
        """Get vendor name from MAC address using OUI database"""
        if not self.oui_db or not mac_address or mac_address == 'Unknown':
            return 'Unknown'
        
        try:
            # Extract first 3 octets (6 hex characters) from MAC address
            # Handle both formats: xx-xx-xx-xx-xx-xx and xx:xx:xx:xx:xx:xx
            mac_clean = mac_address.replace('-', '').replace(':', '').upper()
            if len(mac_clean) >= 6:
                oui_prefix = mac_clean[:6]
                return self.oui_db.get(oui_prefix, 'Unknown')
        except Exception as e:
            pass
        
        return 'Unknown'
    
    def _merge_host_data(self, existing_host, new_host):
        """Merge new host data into existing host data, preserving MAC addresses"""
        merged = existing_host.copy()
        
        # Preserve MAC address if it exists and is not Unknown
        if existing_host.get('mac') and existing_host.get('mac') != 'Unknown':
            merged['mac'] = existing_host['mac']
        elif new_host.get('mac') and new_host.get('mac') != 'Unknown':
            merged['mac'] = new_host['mac']
        
        # Merge hostname (prefer non-Unknown)
        if new_host.get('hostname') and new_host.get('hostname') != 'Unknown':
            merged['hostname'] = new_host['hostname']
        elif not merged.get('hostname') or merged.get('hostname') == 'Unknown':
            merged['hostname'] = existing_host.get('hostname', 'Unknown')
        
        # Merge services (combine lists)
        existing_services = set(existing_host.get('services', []))
        new_services = set(new_host.get('services', []))
        merged['services'] = sorted(list(existing_services | new_services))
        
        # Merge methods (combine)
        existing_method = existing_host.get('method', '')
        new_method = new_host.get('method', '')
        if existing_method and new_method and existing_method != new_method:
            merged['method'] = f"{existing_method}, {new_method}"
        else:
            merged['method'] = new_method or existing_method
        
        return merged
    
    @property
    def name(self) -> str:
        return "network_discover"
    
    @property
    def description(self) -> str:
        return "Discover hosts on the current network using multiple techniques"
    
    @property
    def usage(self) -> str:
        return "network_discover [--range <network_range>] [--timeout <seconds>] [--threads <num>] [--method <method>]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command discovers hosts on the network using multiple discovery techniques:
    - ARP scanning (local network)
    - ICMP ping sweep
    - TCP port scanning
    - UDP scanning
    - NetBIOS discovery
    - mDNS/Bonjour discovery

Options:
    --range <network>     Network range to scan (e.g., 192.168.1.0/24)
    --timeout <seconds>   Timeout for each probe (default: 1)
    --threads <num>       Number of threads to use (default: 50)
    --method <method>     Discovery method: all, arp, ping, tcp, udp, netbios, mdns

Examples:
    network_discover                                    # Auto-detect network and scan
    network_discover --range 192.168.1.0/24            # Scan specific network
    network_discover --method arp --threads 100        # Use ARP only with 100 threads
    network_discover --timeout 2 --method ping         # Use ping with 2s timeout

Note: Some methods require elevated privileges (sudo/Administrator).
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the network discovery command"""
        try:
            # Parse arguments
            options = self._parse_args(args)
            
            # Get network range
            if options['range']:
                network = ipaddress.ip_network(options['range'], strict=False)
            else:
                network = self._get_local_network()
                if not network:
                    print_error("Could not determine local network. Please specify --range")
                    return False
            
            print_info(f"Starting network discovery on {network}")
            print_info(f"Method: {options['method']}, Threads: {options['threads']}, Timeout: {options['timeout']}s")
            print_info("=" * 80)
            
            # Discover hosts
            hosts = self._discover_hosts(network, options)
            
            # Display results
            self._display_results(hosts, network)
            
            return True
            
        except Exception as e:
            print_error(f"Error during network discovery: {str(e)}")
            return False
    
    def _parse_args(self, args):
        """Parse command line arguments"""
        options = {
            'range': None,
            'timeout': 1,
            'threads': 50,
            'method': 'all'
        }
        
        i = 0
        while i < len(args):
            if args[i] == '--range' and i + 1 < len(args):
                options['range'] = args[i + 1]
                i += 2
            elif args[i] == '--timeout' and i + 1 < len(args):
                try:
                    options['timeout'] = int(args[i + 1])
                except ValueError:
                    print_warning(f"Invalid timeout value: {args[i + 1]}, using default")
                i += 2
            elif args[i] == '--threads' and i + 1 < len(args):
                try:
                    options['threads'] = int(args[i + 1])
                except ValueError:
                    print_warning(f"Invalid threads value: {args[i + 1]}, using default")
                i += 2
            elif args[i] == '--method' and i + 1 < len(args):
                options['method'] = args[i + 1].lower()
                i += 2
            else:
                i += 1
        
        return options
    
    def _get_local_network(self):
        """Get the local network range"""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Get network interface info
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if local_ip in line:
                        # Look for subnet mask in nearby lines
                        for j in range(max(0, i-5), min(len(lines), i+5)):
                            if 'Subnet Mask' in lines[j] or 'Masque' in lines[j]:
                                mask_line = lines[j]
                                # Extract mask
                                mask = mask_line.split(':')[-1].strip()
                                if mask:
                                    # Convert mask to CIDR
                                    cidr = self._mask_to_cidr(mask)
                                    if cidr:
                                        network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
                                        return network
            else:
                # Linux/Mac - try to get from route table
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True)
                if result.returncode == 0:
                    # Parse route output to get network
                    for line in result.stdout.split('\n'):
                        if 'src' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'src' and i + 1 < len(parts):
                                    src_ip = parts[i + 1]
                                    # Try common subnets
                                    for cidr in [24, 16, 8]:
                                        try:
                                            network = ipaddress.ip_network(f"{src_ip}/{cidr}", strict=False)
                                            if src_ip in network:
                                                return network
                                        except:
                                            continue
            
            # Fallback to common private networks
            for cidr in [24, 16, 8]:
                try:
                    network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
                    if local_ip in network:
                        return network
                except:
                    continue
            
            return None
            
        except Exception as e:
            print_warning(f"Could not determine local network: {e}")
            return None
    
    def _mask_to_cidr(self, mask):
        """Convert subnet mask to CIDR notation"""
        try:
            parts = mask.split('.')
            if len(parts) != 4:
                return None
            
            binary = ''
            for part in parts:
                binary += format(int(part), '08b')
            
            return binary.count('1')
        except:
            return None
    
    def _discover_hosts(self, network, options):
        """Discover hosts using specified methods"""
        hosts = {}
        method = options['method']
        
        if method == 'all' or method == 'arp':
            print_info("Performing ARP scan...")
            arp_hosts = self._arp_scan(network, options)
            # Merge ARP hosts intelligently
            for ip, host_data in arp_hosts.items():
                if ip in hosts:
                    hosts[ip] = self._merge_host_data(hosts[ip], host_data)
                else:
                    hosts[ip] = host_data
        
        if method == 'all' or method == 'ping':
            print_info("Performing ICMP ping sweep...")
            ping_hosts = self._ping_sweep(network, options)
            # Merge ping hosts intelligently (preserve MAC from ARP)
            for ip, host_data in ping_hosts.items():
                if ip in hosts:
                    hosts[ip] = self._merge_host_data(hosts[ip], host_data)
                else:
                    hosts[ip] = host_data
        
        if method == 'all' or method == 'tcp':
            print_info("Performing TCP port scan...")
            tcp_hosts = self._tcp_scan(network, options)
            # Merge TCP hosts intelligently (preserve MAC from ARP)
            for ip, host_data in tcp_hosts.items():
                if ip in hosts:
                    hosts[ip] = self._merge_host_data(hosts[ip], host_data)
                else:
                    hosts[ip] = host_data
        
        if method == 'all' or method == 'udp':
            print_info("Performing UDP scan...")
            udp_hosts = self._udp_scan(network, options)
            # Merge UDP hosts intelligently (preserve MAC from ARP)
            for ip, host_data in udp_hosts.items():
                if ip in hosts:
                    hosts[ip] = self._merge_host_data(hosts[ip], host_data)
                else:
                    hosts[ip] = host_data
        
        if method == 'all' or method == 'netbios':
            print_info("Performing NetBIOS discovery...")
            netbios_hosts = self._netbios_scan(network, options)
            # Merge NetBIOS hosts intelligently (preserve MAC from ARP)
            for ip, host_data in netbios_hosts.items():
                if ip in hosts:
                    hosts[ip] = self._merge_host_data(hosts[ip], host_data)
                else:
                    hosts[ip] = host_data
        
        if method == 'all' or method == 'mdns':
            print_info("Performing mDNS/Bonjour discovery...")
            mdns_hosts = self._mdns_scan(network, options)
            # Merge mDNS hosts intelligently (preserve MAC from ARP)
            for ip, host_data in mdns_hosts.items():
                if ip in hosts:
                    hosts[ip] = self._merge_host_data(hosts[ip], host_data)
                else:
                    hosts[ip] = host_data
        
        # Add vendor information for all hosts with MAC addresses
        for ip in hosts:
            if hosts[ip].get('mac') and hosts[ip].get('mac') != 'Unknown':
                vendor = self._get_mac_vendor(hosts[ip]['mac'])
                hosts[ip]['vendor'] = vendor
        
        return hosts
    
    def _arp_scan(self, network, options):
        """Perform ARP scan"""
        hosts = {}
        
        try:
            if platform.system() == "Windows":
                # Windows ARP scan
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        # Skip empty lines, headers, and interface lines
                        if not line or 'Interface' in line or 'Adresse Internet' in line or 'Internet Address' in line or 'Type' in line:
                            continue
                        
                        # Try to match IP address pattern
                        # Format can be: "10.81.7.4             b4-00-16-0b-0f-c7     dynamique"
                        # or: "10.81.7.4 (192.168.1.1)     b4-00-16-0b-0f-c7     dynamique"
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            try:
                                ip = ip_match.group(1)
                                # Extract MAC address (format: xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx)
                                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                                mac = mac_match.group(0) if mac_match else 'Unknown'
                                
                                # Check if IP is in the target network
                                if ipaddress.ip_address(ip) in network:
                                    hosts[ip] = {
                                        'ip': ip,
                                        'mac': mac,
                                        'hostname': 'Unknown',
                                        'services': [],
                                        'method': 'ARP'
                                    }
                            except Exception as e:
                                continue
            else:
                # Linux/Mac ARP scan
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '(' in line and ')' in line:
                            try:
                                ip = line.split('(')[1].split(')')[0]
                                parts = line.split()
                                mac = parts[3] if len(parts) > 3 else 'Unknown'
                                hostname = parts[0] if len(parts) > 0 else 'Unknown'
                                if ipaddress.ip_address(ip) in network:
                                    hosts[ip] = {
                                        'ip': ip,
                                        'mac': mac,
                                        'hostname': hostname,
                                        'services': [],
                                        'method': 'ARP'
                                    }
                            except:
                                continue
        except Exception as e:
            print_warning(f"ARP scan failed: {e}")
        
        return hosts
    
    def _ping_sweep(self, network, options):
        """Perform ICMP ping sweep"""
        hosts = {}
        
        def ping_host(ip):
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['ping', '-n', '1', '-w', str(options['timeout'] * 1000), str(ip)], 
                                          capture_output=True, text=True, timeout=options['timeout'] + 1)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', str(options['timeout']), str(ip)], 
                                          capture_output=True, text=True, timeout=options['timeout'] + 1)
                
                if result.returncode == 0:
                    return str(ip)
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=options['threads']) as executor:
            futures = {executor.submit(ping_host, str(ip)): ip for ip in network.hosts()}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    hosts[result] = {
                        'ip': result,
                        'mac': 'Unknown',
                        'hostname': 'Unknown',
                        'services': [],
                        'method': 'PING'
                    }
        
        return hosts
    
    def _tcp_scan(self, network, options):
        """Perform TCP port scan"""
        hosts = {}
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 5900, 8080]
        
        def scan_host(ip):
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(options['timeout'])
                    result = sock.connect_ex((str(ip), port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            if open_ports:
                return str(ip), open_ports
            return None, []
        
        with ThreadPoolExecutor(max_workers=options['threads']) as executor:
            futures = {executor.submit(scan_host, ip): ip for ip in network.hosts()}
            
            for future in as_completed(futures):
                ip, ports = future.result()
                if ip:
                    hosts[ip] = {
                        'ip': ip,
                        'mac': 'Unknown',
                        'hostname': 'Unknown',
                        'services': [f"tcp/{port}" for port in ports],
                        'method': 'TCP'
                    }
        
        return hosts
    
    def _udp_scan(self, network, options):
        """Perform UDP scan"""
        hosts = {}
        common_ports = [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 500, 514, 520, 631, 1434]
        
        def scan_host(ip):
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(options['timeout'])
                    sock.sendto(b'\x00', (str(ip), port))
                    sock.recvfrom(1024)
                    open_ports.append(port)
                except:
                    pass
                finally:
                    sock.close()
            
            if open_ports:
                return str(ip), open_ports
            return None, []
        
        with ThreadPoolExecutor(max_workers=options['threads']) as executor:
            futures = {executor.submit(scan_host, ip): ip for ip in network.hosts()}
            
            for future in as_completed(futures):
                ip, ports = future.result()
                if ip:
                    hosts[ip] = {
                        'ip': ip,
                        'mac': 'Unknown',
                        'hostname': 'Unknown',
                        'services': [f"udp/{port}" for port in ports],
                        'method': 'UDP'
                    }
        
        return hosts
    
    def _netbios_scan(self, network, options):
        """Perform NetBIOS scan"""
        hosts = {}
        
        def scan_host(ip):
            try:
                # Try to get NetBIOS name
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(options['timeout'])
                
                # NetBIOS name query
                query = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
                sock.sendto(query, (str(ip), 137))
                
                response, addr = sock.recvfrom(1024)
                if response:
                    # Parse NetBIOS response (simplified)
                    if len(response) > 56:
                        name_length = response[56]
                        if name_length > 0 and name_length < 16:
                            name = response[57:57+name_length].decode('ascii', errors='ignore')
                            return str(ip), name
            except:
                pass
            finally:
                sock.close()
            
            return None, None
        
        with ThreadPoolExecutor(max_workers=options['threads']) as executor:
            futures = {executor.submit(scan_host, ip): ip for ip in network.hosts()}
            
            for future in as_completed(futures):
                ip, hostname = future.result()
                if ip:
                    hosts[ip] = {
                        'ip': ip,
                        'mac': 'Unknown',
                        'hostname': hostname or 'Unknown',
                        'services': ['netbios/137'],
                        'method': 'NetBIOS'
                    }
        
        return hosts
    
    def _mdns_scan(self, network, options):
        """Perform mDNS/Bonjour scan"""
        hosts = {}
        
        try:
            # Try to discover mDNS services
            if platform.system() == "Windows":
                # Windows - use nslookup for mDNS
                result = subprocess.run(['nslookup', '-type=PTR', '_services._dns-sd._udp.local'], 
                                     capture_output=True, text=True, timeout=options['timeout'])
            else:
                # Linux/Mac - use avahi-browse or dns-sd
                result = subprocess.run(['avahi-browse', '-at'], capture_output=True, text=True, timeout=options['timeout'])
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IPv4' in line or 'IPv6' in line:
                        parts = line.split()
                        for part in parts:
                            try:
                                ip = ipaddress.ip_address(part)
                                if ip in network:
                                    hosts[str(ip)] = {
                                        'ip': str(ip),
                                        'mac': 'Unknown',
                                        'hostname': 'mDNS Device',
                                        'services': ['mdns'],
                                        'method': 'mDNS'
                                    }
                            except:
                                continue
        except Exception as e:
            print_warning(f"mDNS scan failed: {e}")
        
        return hosts
    
    def _display_results(self, hosts, network):
        """Display discovery results"""
        if not hosts:
            print_warning("No hosts discovered")
            return
        
        print_success(f"Discovered {len(hosts)} hosts on {network}")
        print_info("=" * 100)
        print_info(f"{'IP Address':<15} {'MAC Address':<17} {'Vendor':<25} {'Hostname':<20} {'Services':<25} {'Method'}")
        print_info("-" * 100)
        
        for ip, info in sorted(hosts.items(), key=lambda x: ipaddress.ip_address(x[0])):
            services = ', '.join(info['services'][:2])  # Show first 2 services
            if len(info['services']) > 2:
                services += f" (+{len(info['services'])-2} more)"
            
            vendor = info.get('vendor', 'Unknown')
            # Truncate vendor name if too long
            if len(vendor) > 24:
                vendor = vendor[:21] + "..."
            
            print_info(f"{info['ip']:<15} {info['mac']:<17} {vendor:<25} {info['hostname']:<20} {services:<25} {info['method']}")
        
        print_info("=" * 100)
        print_info(f"Total: {len(hosts)} hosts discovered")
        
        # Summary by method
        methods = {}
        for info in hosts.values():
            method = info['method']
            methods[method] = methods.get(method, 0) + 1
        
        print_info("\nDiscovery summary:")
        for method, count in methods.items():
            print_info(f"  {method}: {count} hosts")
