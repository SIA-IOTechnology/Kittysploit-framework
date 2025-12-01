#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MyIP command implementation - Display local IP addresses
"""

import socket
import subprocess
import platform
import json
import requests
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class MyIPCommand(BaseCommand):
    """Command to display local and public IP addresses"""
    
    @property
    def name(self) -> str:
        return "myip"
    
    @property
    def description(self) -> str:
        return "Display local and public IP addresses"
    
    @property
    def usage(self) -> str:
        return "myip [--public] [--local] [--all] [--json]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command displays IP address information for the current machine:
    - Local IP addresses (all network interfaces)
    - Public IP address (external/WAN)
    - Network interface details
    - Gateway information

Options:
    --public     Show only public IP address
    --local      Show only local IP addresses
    --all        Show all information (default)
    --json       Output in JSON format

Examples:
    myip                    # Show all IP information
    myip --public          # Show only public IP
    myip --local           # Show only local IPs
    myip --json            # Output in JSON format

Note: Public IP detection requires internet connectivity.
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the myip command"""
        try:
            # Parse arguments
            options = self._parse_args(args)
            
            # Collect IP information
            ip_info = self._collect_ip_info()
            
            # Display results based on options
            if options['json']:
                self._display_json(ip_info, options)
            else:
                self._display_formatted(ip_info, options)
            
            return True
            
        except Exception as e:
            print_error(f"Error getting IP information: {str(e)}")
            return False
    
    def _parse_args(self, args):
        """Parse command line arguments"""
        options = {
            'public': False,
            'local': False,
            'all': True,
            'json': False
        }
        
        for arg in args:
            if arg == '--public':
                options['public'] = True
                options['all'] = False
            elif arg == '--local':
                options['local'] = True
                options['all'] = False
            elif arg == '--all':
                options['all'] = True
            elif arg == '--json':
                options['json'] = True
        
        return options
    
    def _collect_ip_info(self):
        """Collect all IP information"""
        ip_info = {
            'local_ips': [],
            'public_ip': None,
            'gateway': None,
            'interfaces': [],
            'hostname': socket.gethostname()
        }
        
        # Get local IP addresses
        ip_info['local_ips'] = self._get_local_ips()
        
        # Get network interfaces
        ip_info['interfaces'] = self._get_network_interfaces()
        
        # Get gateway
        ip_info['gateway'] = self._get_gateway()
        
        # Get public IP
        ip_info['public_ip'] = self._get_public_ip()
        
        return ip_info
    
    def _get_local_ips(self):
        """Get all local IP addresses"""
        local_ips = []
        
        try:
            # Method 1: Using socket connection to external address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip not in local_ips and not local_ip.startswith('127.'):
                local_ips.append(local_ip)
        except:
            pass
        
        try:
            # Method 2: Get all network interfaces
            import netifaces
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        if ip not in local_ips and not ip.startswith('127.'):
                            local_ips.append(ip)
        except ImportError:
            # Fallback method using system commands
            system_ips = self._get_local_ips_system()
            for ip in system_ips:
                if ip not in local_ips and not ip.startswith('127.'):
                    local_ips.append(ip)
        except:
            pass
        
        return local_ips
    
    def _get_local_ips_system(self):
        """Get local IPs using system commands"""
        local_ips = []
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'IPv4 Address' in line or 'Adresse IPv4' in line:
                            ip = line.split(':')[-1].strip()
                            if ip and not ip.startswith('127.'):
                                local_ips.append(ip)
            else:
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                if result.returncode == 0:
                    ips = result.stdout.strip().split()
                    for ip in ips:
                        if not ip.startswith('127.'):
                            local_ips.append(ip)
        except:
            pass
        
        return local_ips
    
    def _get_network_interfaces(self):
        """Get network interface information"""
        interfaces = []
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                if result.returncode == 0:
                    current_interface = {}
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line and not line.startswith(' '):
                            if current_interface:
                                interfaces.append(current_interface)
                            current_interface = {'name': line, 'details': []}
                        elif line and current_interface:
                            current_interface['details'].append(line)
                    if current_interface:
                        interfaces.append(current_interface)
            else:
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
                if result.returncode == 0:
                    current_interface = {}
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line.startswith(('1:', '2:', '3:', '4:', '5:', '6:', '7:', '8:', '9:')):
                            if current_interface:
                                interfaces.append(current_interface)
                            interface_name = line.split(':')[1].strip()
                            current_interface = {'name': interface_name, 'details': []}
                        elif line and current_interface:
                            current_interface['details'].append(line)
                    if current_interface:
                        interfaces.append(current_interface)
        except:
            pass
        
        return interfaces
    
    def _get_gateway(self):
        """Get gateway IP address"""
        try:
            if platform.system() == "Windows":
                # Try ipconfig first
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Default Gateway' in line or 'Passerelle par défaut' in line:
                            gateway = line.split(':')[-1].strip()
                            if gateway and gateway != '' and gateway != '::' and '.' in gateway:
                                return gateway
                
                # Try route command as fallback
                result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '0.0.0.0' in line and 'Gateway' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == '0.0.0.0' and i + 1 < len(parts):
                                    gateway = parts[i + 1]
                                    if '.' in gateway:
                                        return gateway
            else:
                # Linux/Mac methods
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'default via' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'via' and i + 1 < len(parts):
                                    return parts[i + 1]
        except:
            pass
        
        return None
    
    def _get_public_ip(self):
        """Get public IP address"""
        public_ip_services = [
            'https://api.ipify.org',
            'https://ipinfo.io/ip',
            'https://icanhazip.com',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in public_ip_services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # Validate IP format
                    socket.inet_aton(ip)
                    return ip
            except:
                continue
        
        return None
    
    def _display_formatted(self, ip_info, options):
        """Display IP information in formatted text"""
        print_info("IP Address Information")
        print_info("=" * 50)
        
        # Hostname
        print_info(f"Hostname: {ip_info['hostname']}")
        print_info("")
        
        # Local IPs
        if options['all'] or options['local']:
            if ip_info['local_ips']:
                print_success("Local IP Addresses:")
                for i, ip in enumerate(ip_info['local_ips'], 1):
                    print_info(f"  {i}. {ip}")
            else:
                print_warning("No local IP addresses found")
            print_info("")
        
        # Public IP
        if options['all'] or options['public']:
            if ip_info['public_ip']:
                print_success(f"Public IP Address: {ip_info['public_ip']}")
            else:
                print_warning("Could not determine public IP address")
            print_info("")
        
        # Gateway
        if options['all']:
            if ip_info['gateway']:
                print_info(f"Gateway: {ip_info['gateway']}")
            else:
                print_warning("Could not determine gateway")
            print_info("")
        
        # Network interfaces (if all) - simplified
        if options['all']:
            print_info("Network Interfaces:")
            # Show the local IPs we already found with interface names
            for i, ip in enumerate(ip_info['local_ips'], 1):
                if i == 1:
                    print_info(f"  Primary: {ip}")
                else:
                    print_info(f"  Secondary {i-1}: {ip}")
            print_info("")
    
    def _display_json(self, ip_info, options):
        """Display IP information in JSON format"""
        output = {}
        
        if options['all'] or options['local']:
            output['local_ips'] = ip_info['local_ips']
        
        if options['all'] or options['public']:
            output['public_ip'] = ip_info['public_ip']
        
        if options['all']:
            output['hostname'] = ip_info['hostname']
            output['gateway'] = ip_info['gateway']
            output['interfaces'] = ip_info['interfaces']
        
        print(json.dumps(output, indent=2))
