from kittysploit import *
from lib.post.linux.system import System
import re

class Module(Post, System):

    __info__ = {
        "name": "Linux Internal Network Scanner",
        "description": "Scan internal network from compromised Linux machine for pivoting targets",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }

    network_range = OptString("", "Network range to scan (e.g., 192.168.1.0/24 or 10.0.0.0/24)", required=True)
    scan_type = OptString("all", "Scan type: all, arp, ping, tcp, udp", required=False)
    ports = OptString("22,80,443,3389,8080", "TCP ports to scan (comma-separated)", required=False)
    timeout = OptInteger(1, "Timeout per host in seconds", required=False)

    def run(self):
        """Scan internal network from compromised machine"""
        
        print_status("Scanning internal network from compromised machine...")
        print_info(f"Network range: {self.network_range.value}")
        print_info(f"Scan type: {self.scan_type.value}")
        
        if not self.network_range.value:
            print_error("Network range is required")
            print_info("Example: 192.168.1.0/24 or 10.0.0.0/24")
            return False
        
        # Detect network if not provided
        if "/" not in self.network_range.value:
            print_status("Auto-detecting network range...")
            detected_network = self._detect_network()
            if detected_network:
                print_info(f"Detected network: {detected_network}")
                self.network_range.value = detected_network
            else:
                print_error("Could not auto-detect network. Please specify network range.")
                return False
        
        results = {}
        
        # Perform scans based on type
        if self.scan_type.value == "all" or self.scan_type.value == "arp":
            print_status("Performing ARP scan...")
            arp_results = self._arp_scan()
            results.update(arp_results)
        
        if self.scan_type.value == "all" or self.scan_type.value == "ping":
            print_status("Performing ICMP ping sweep...")
            ping_results = self._ping_sweep()
            results.update(ping_results)
        
        if self.scan_type.value == "all" or self.scan_type.value == "tcp":
            print_status("Performing TCP port scan...")
            tcp_results = self._tcp_scan()
            results.update(tcp_results)
        
        if self.scan_type.value == "all" or self.scan_type.value == "udp":
            print_status("Performing UDP scan...")
            udp_results = self._udp_scan()
            results.update(udp_results)
        
        # Display results
        self._display_results(results)
        
        return True
    
    def _detect_network(self):
        """Auto-detect network range from compromised machine"""
        try:
            # Get default route
            route_output = self.cmd_exec("ip route | grep default 2>/dev/null || route -n | grep '^0.0.0.0' 2>/dev/null")
            if route_output:
                # Extract interface
                if "dev" in route_output:
                    parts = route_output.split()
                    if "dev" in parts:
                        idx = parts.index("dev")
                        if idx + 1 < len(parts):
                            interface = parts[idx + 1]
                            
                            # Get IP and netmask for this interface
                            ip_output = self.cmd_exec(f"ip addr show {interface} 2>/dev/null | grep 'inet '")
                            if ip_output:
                                # Extract IP and CIDR
                                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', ip_output)
                                if match:
                                    ip = match.group(1)
                                    cidr = match.group(2)
                                    # Calculate network
                                    ip_parts = ip.split('.')
                                    if cidr == "24":
                                        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                                        return network
                                    elif cidr == "16":
                                        network = f"{ip_parts[0]}.{ip_parts[1]}.0.0/16"
                                        return network
            
            # Fallback: try ifconfig
            ifconfig_output = self.cmd_exec("ifconfig 2>/dev/null | grep -A 1 'inet '")
            if ifconfig_output:
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+).*netmask\s+(\d+\.\d+\.\d+\.\d+)', ifconfig_output)
                if match:
                    ip = match.group(1)
                    netmask = match.group(2)
                    # Convert netmask to CIDR (simplified)
                    if netmask == "255.255.255.0":
                        ip_parts = ip.split('.')
                        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            return None
            
        except Exception as e:
            print_warning(f"Error detecting network: {e}")
            return None
    
    def _arp_scan(self):
        """Perform ARP scan"""
        results = {}
        try:
            # Extract network base
            network_base = self.network_range.value.split('/')[0]
            base_parts = network_base.split('.')
            
            if len(base_parts) == 4:
                # Assume /24 for now
                base = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
                
                print_info(f"Scanning {base}.0/24 with ARP...")
                
                # Use arp-scan if available
                if self.command_exists('arp-scan'):
                    arp_cmd = f"arp-scan --local --quiet 2>/dev/null | grep -E '^[0-9]'"
                    output = self.cmd_exec(arp_cmd)
                    if output:
                        for line in output.strip().split('\n'):
                            if line.strip():
                                parts = line.split()
                                if len(parts) >= 2:
                                    ip = parts[0]
                                    mac = parts[1]
                                    results[ip] = {
                                        'ip': ip,
                                        'mac': mac,
                                        'method': 'arp',
                                        'alive': True
                                    }
                else:
                    # Use arp table
                    arp_output = self.cmd_exec("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
                    if arp_output:
                        for line in arp_output.strip().split('\n'):
                            if line.strip():
                                # Parse ARP entry
                                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                                if match:
                                    ip = match.group(1)
                                    mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                                    mac = mac_match.group(0) if mac_match else "unknown"
                                    results[ip] = {
                                        'ip': ip,
                                        'mac': mac,
                                        'method': 'arp',
                                        'alive': True
                                    }
            
        except Exception as e:
            print_warning(f"ARP scan error: {e}")
        
        return results
    
    def _ping_sweep(self):
        """Perform ICMP ping sweep"""
        results = {}
        try:
            network_base = self.network_range.value.split('/')[0]
            base_parts = network_base.split('.')
            
            if len(base_parts) == 4:
                base = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
                
                print_info(f"Ping sweeping {base}.0/24...")
                
                # Use fping if available (faster)
                if self.command_exists('fping'):
                    fping_cmd = f"fping -a -g {base}.0 {base}.255 -q 2>/dev/null"
                    output = self.cmd_exec(fping_cmd)
                    if output:
                        for ip in output.strip().split('\n'):
                            if ip.strip():
                                results[ip.strip()] = {
                                    'ip': ip.strip(),
                                    'method': 'ping',
                                    'alive': True
                                }
                else:
                    # Use ping in loop (slower)
                    print_info("Using ping (this may take a while)...")
                    for i in range(1, 255):
                        ip = f"{base}.{i}"
                        ping_cmd = f"ping -c 1 -W {self.timeout.value} {ip} 2>/dev/null | grep '1 received'"
                        result = self.cmd_exec(ping_cmd)
                        if result and result.strip():
                            results[ip] = {
                                'ip': ip,
                                'method': 'ping',
                                'alive': True
                            }
                            print_info(f"  Found: {ip}")
        
        except Exception as e:
            print_warning(f"Ping sweep error: {e}")
        
        return results
    
    def _tcp_scan(self):
        """Perform TCP port scan"""
        results = {}
        try:
            # Get alive hosts first
            alive_hosts = []
            
            # Quick ping to find alive hosts
            network_base = self.network_range.value.split('/')[0]
            base_parts = network_base.split('.')
            
            if len(base_parts) == 4:
                base = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
                
                # Use nmap if available
                if self.command_exists('nmap'):
                    ports = self.ports.value.replace(' ', '')
                    nmap_cmd = f"nmap -sn {self.network_range.value} 2>/dev/null | grep -E '^Nmap scan report' | awk '{{print $5}}'"
                    hosts_output = self.cmd_exec(nmap_cmd)
                    if hosts_output:
                        alive_hosts = [h.strip() for h in hosts_output.strip().split('\n') if h.strip()]
                else:
                    # Use fping or ping
                    if self.command_exists('fping'):
                        fping_output = self.cmd_exec(f"fping -a -g {base}.0 {base}.255 -q 2>/dev/null")
                        if fping_output:
                            alive_hosts = [h.strip() for h in fping_output.strip().split('\n') if h.strip()]
                
                # Scan ports on alive hosts
                ports_list = [p.strip() for p in self.ports.value.split(',') if p.strip()]
                
                print_info(f"Scanning {len(ports_list)} port(s) on {len(alive_hosts)} host(s)...")
                
                for host in alive_hosts[:50]:  # Limit to 50 hosts
                    if host not in results:
                        results[host] = {
                            'ip': host,
                            'ports': {},
                            'method': 'tcp'
                        }
                    
                    for port in ports_list:
                        try:
                            port_num = int(port)
                            # Use nc or bash /dev/tcp
                            nc_cmd = f"timeout {self.timeout.value} bash -c '</dev/tcp/{host}/{port_num}' 2>/dev/null && echo 'open'"
                            result = self.cmd_exec(nc_cmd)
                            if result and 'open' in result:
                                results[host]['ports'][port_num] = 'open'
                                print_info(f"  {host}:{port_num} - OPEN")
                        except:
                            pass
        
        except Exception as e:
            print_warning(f"TCP scan error: {e}")
        
        return results
    
    def _udp_scan(self):
        """Perform UDP scan"""
        results = {}
        try:
            print_warning("UDP scanning is slower and less reliable")
            print_info("Scanning common UDP ports...")
            
            # UDP scanning is complex and slow, so we'll do a basic check
            network_base = self.network_range.value.split('/')[0]
            base_parts = network_base.split('.')
            
            if len(base_parts) == 4:
                base = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
                
                # Use nmap for UDP if available
                if self.command_exists('nmap'):
                    nmap_cmd = f"nmap -sU --top-ports 10 {self.network_range.value} 2>/dev/null"
                    output = self.cmd_exec(nmap_cmd)
                    if output:
                        # Parse nmap output
                        current_host = None
                        for line in output.strip().split('\n'):
                            if 'Nmap scan report' in line:
                                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                                if match:
                                    current_host = match.group(1)
                                    if current_host not in results:
                                        results[current_host] = {
                                            'ip': current_host,
                                            'ports': {},
                                            'method': 'udp'
                                        }
                            elif current_host and '/udp' in line and 'open' in line:
                                match = re.search(r'(\d+)/udp', line)
                                if match:
                                    port = match.group(1)
                                    results[current_host]['ports'][int(port)] = 'open'
        
        except Exception as e:
            print_warning(f"UDP scan error: {e}")
        
        return results
    
    def _display_results(self, results):
        """Display scan results"""
        print_status("="*60)
        print_status("Scan Results")
        print_status("="*60)
        
        if not results:
            print_warning("No hosts found")
            return
        
        # Group by IP
        hosts = {}
        for ip, data in results.items():
            if ip not in hosts:
                hosts[ip] = {
                    'ip': ip,
                    'methods': [],
                    'ports': {},
                    'mac': None
                }
            
            if 'method' in data:
                if data['method'] not in hosts[ip]['methods']:
                    hosts[ip]['methods'].append(data['method'])
            
            if 'mac' in data:
                hosts[ip]['mac'] = data['mac']
            
            if 'ports' in data:
                hosts[ip]['ports'].update(data['ports'])
        
        print_success(f"Found {len(hosts)} host(s)")
        print_info("")
        
        for ip, data in sorted(hosts.items()):
            print_info(f"Host: {ip}")
            if data['mac']:
                print_info(f"  MAC: {data['mac']}")
            if data['methods']:
                print_info(f"  Detected by: {', '.join(data['methods'])}")
            if data['ports']:
                open_ports = [str(p) for p, status in data['ports'].items() if status == 'open']
                if open_ports:
                    print_info(f"  Open ports: {', '.join(open_ports)}")
            print_info("")

