from kittysploit import *
from lib.post.linux.system import System

class Module(Post, System):

    __info__ = {
        "name": "Linux Network Enumeration",
        "description": "Enumerate network interfaces, connections, routes, firewall rules, and DNS configuration",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }

    def run(self):
        """Enumerate network information"""
        
        print_status("Starting network enumeration...")
        
        # 1. Network Interfaces
        self._enum_interfaces()
        
        # 2. Routing Information
        self._enum_routes()
        
        # 3. Active Connections
        self._enum_connections()
        
        # 4. Listening Ports
        self._enum_listening_ports()
        
        # 5. Firewall Rules
        self._enum_firewall()
        
        # 6. DNS Configuration
        self._enum_dns()
        
        # 7. Network History
        self._enum_network_history()
        
        print_success("Network enumeration completed")
        return True
    
    def _enum_interfaces(self):
        """Enumerate network interfaces"""
        print_status("="*60)
        print_status("Network Interfaces")
        print_status("="*60)
        
        try:
            # Get all interfaces using ip command (preferred)
            if self.command_exists('ip'):
                interfaces_output = self.cmd_exec("ip -o addr show 2>/dev/null")
                if interfaces_output and "error" not in interfaces_output.lower():
                    print_info("Network Interfaces (ip addr):")
                    for line in interfaces_output.strip().split('\n'):
                        if line.strip():
                            print_info(f"  {line}")
                else:
                    # Fallback to ifconfig
                    ifconfig_output = self.cmd_exec("ifconfig -a 2>/dev/null || ipconfig 2>/dev/null")
                    if ifconfig_output:
                        print_info("Network Interfaces (ifconfig):")
                        print_info(ifconfig_output)
            else:
                # Fallback to ifconfig
                ifconfig_output = self.cmd_exec("ifconfig -a 2>/dev/null")
                if ifconfig_output:
                    print_info("Network Interfaces (ifconfig):")
                    print_info(ifconfig_output)
            
            # Get MAC addresses
            print_status("MAC Addresses:")
            mac_output = self.cmd_exec("cat /sys/class/net/*/address 2>/dev/null | head -20")
            if mac_output and mac_output.strip():
                for line in mac_output.strip().split('\n'):
                    if line.strip():
                        interface = line.split('/')[3] if '/' in line else 'unknown'
                        print_info(f"  {interface}: {line.strip()}")
            
            # Get interface statistics
            print_status("Interface Statistics:")
            stats_output = self.cmd_exec("cat /proc/net/dev 2>/dev/null")
            if stats_output:
                print_info(stats_output)
                
        except Exception as e:
            print_warning(f"Error enumerating interfaces: {e}")
    
    def _enum_routes(self):
        """Enumerate routing information"""
        print_status("="*60)
        print_status("Routing Information")
        print_status("="*60)
        
        try:
            # Get routing table using ip command
            if self.command_exists('ip'):
                routes_output = self.cmd_exec("ip route show 2>/dev/null")
                if routes_output:
                    print_info("Routing Table (ip route):")
                    for line in routes_output.strip().split('\n'):
                        if line.strip():
                            print_info(f"  {line}")
            else:
                # Fallback to route command
                route_output = self.cmd_exec("route -n 2>/dev/null || route 2>/dev/null")
                if route_output:
                    print_info("Routing Table (route):")
                    print_info(route_output)
            
            # Get default gateway
            print_status("Default Gateway:")
            gateway = self.cmd_exec("ip route | grep default 2>/dev/null || route -n | grep '^0.0.0.0' 2>/dev/null")
            if gateway:
                print_info(f"  {gateway.strip()}")
            
            # Get ARP table
            print_status("ARP Table:")
            arp_output = self.cmd_exec("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
            if arp_output:
                for line in arp_output.strip().split('\n'):
                    if line.strip():
                        print_info(f"  {line}")
            
        except Exception as e:
            print_warning(f"Error enumerating routes: {e}")
    
    def _enum_connections(self):
        """Enumerate active network connections"""
        print_status("="*60)
        print_status("Active Network Connections")
        print_status("="*60)
        
        try:
            # Try ss command first (modern replacement for netstat)
            if self.command_exists('ss'):
                # TCP connections
                tcp_output = self.cmd_exec("ss -tunap 2>/dev/null | head -50")
                if tcp_output:
                    print_info("TCP Connections (ss):")
                    for line in tcp_output.strip().split('\n'):
                        if line.strip() and not line.strip().startswith('State'):
                            print_info(f"  {line}")
                
                # UDP connections
                udp_output = self.cmd_exec("ss -uap 2>/dev/null | head -30")
                if udp_output:
                    print_info("UDP Connections (ss):")
                    for line in udp_output.strip().split('\n'):
                        if line.strip() and not line.strip().startswith('State'):
                            print_info(f"  {line}")
            else:
                # Fallback to netstat
                if self.command_exists('netstat'):
                    tcp_output = self.cmd_exec("netstat -tunap 2>/dev/null | head -50")
                    if tcp_output:
                        print_info("Network Connections (netstat):")
                        print_info(tcp_output)
            
            # Get established connections count
            established = self.cmd_exec("ss -tn state established 2>/dev/null | wc -l || netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l")
            if established and established.strip().isdigit():
                print_info(f"Established connections: {established.strip()}")
                
        except Exception as e:
            print_warning(f"Error enumerating connections: {e}")
    
    def _enum_listening_ports(self):
        """Enumerate listening ports and services"""
        print_status("="*60)
        print_status("Listening Ports and Services")
        print_status("="*60)
        
        try:
            # Get listening ports using ss
            if self.command_exists('ss'):
                listen_output = self.cmd_exec("ss -tlnp 2>/dev/null")
                if listen_output:
                    print_info("Listening TCP Ports (ss):")
                    for line in listen_output.strip().split('\n'):
                        if line.strip() and not line.strip().startswith('State'):
                            print_info(f"  {line}")
                
                udp_listen = self.cmd_exec("ss -ulnp 2>/dev/null")
                if udp_listen:
                    print_info("Listening UDP Ports (ss):")
                    for line in udp_listen.strip().split('\n'):
                        if line.strip() and not line.strip().startswith('State'):
                            print_info(f"  {line}")
            else:
                # Fallback to netstat
                if self.command_exists('netstat'):
                    listen_output = self.cmd_exec("netstat -tlnp 2>/dev/null || netstat -tln 2>/dev/null")
                    if listen_output:
                        print_info("Listening Ports (netstat):")
                        print_info(listen_output)
            
            # Try to identify services on common ports
            print_status("Common Services:")
            common_ports = {
                '22': 'SSH',
                '23': 'Telnet',
                '25': 'SMTP',
                '53': 'DNS',
                '80': 'HTTP',
                '110': 'POP3',
                '143': 'IMAP',
                '443': 'HTTPS',
                '3306': 'MySQL',
                '5432': 'PostgreSQL',
                '6379': 'Redis',
                '8080': 'HTTP-Proxy',
                '8443': 'HTTPS-Alt'
            }
            
            # Check which common ports are listening
            for port, service in common_ports.items():
                check = self.cmd_exec(f"ss -tln 2>/dev/null | grep ':{port} ' || netstat -tln 2>/dev/null | grep ':{port} '")
                if check and check.strip():
                    print_info(f"  Port {port}: {service} (LISTENING)")
                    
        except Exception as e:
            print_warning(f"Error enumerating listening ports: {e}")
    
    def _enum_firewall(self):
        """Enumerate firewall rules"""
        print_status("="*60)
        print_status("Firewall Rules")
        print_status("="*60)
        
        try:
            # Check for iptables
            if self.command_exists('iptables'):
                print_status("iptables Rules:")
                # Get iptables rules (requires root for full output)
                iptables_output = self.cmd_exec("iptables -L -n -v 2>/dev/null")
                if iptables_output and "Permission denied" not in iptables_output:
                    print_info(iptables_output)
                else:
                    print_warning("  Cannot read iptables rules (requires root privileges)")
                
                # Get NAT rules
                nat_output = self.cmd_exec("iptables -t nat -L -n -v 2>/dev/null")
                if nat_output and "Permission denied" not in nat_output:
                    print_status("NAT Rules:")
                    print_info(nat_output)
            
            # Check for firewalld
            if self.command_exists('firewall-cmd'):
                print_status("firewalld Status:")
                firewalld_status = self.cmd_exec("firewall-cmd --state 2>/dev/null")
                if firewalld_status:
                    print_info(f"  Status: {firewalld_status.strip()}")
                
                firewalld_zones = self.cmd_exec("firewall-cmd --list-all-zones 2>/dev/null")
                if firewalld_zones:
                    print_info("Firewalld Zones:")
                    print_info(firewalld_zones)
            
            # Check for UFW
            if self.command_exists('ufw'):
                print_status("UFW Status:")
                ufw_status = self.cmd_exec("ufw status verbose 2>/dev/null")
                if ufw_status:
                    print_info(ufw_status)
            
            # Check for nftables (modern replacement for iptables)
            if self.command_exists('nft'):
                print_status("nftables Rules:")
                nft_output = self.cmd_exec("nft list ruleset 2>/dev/null")
                if nft_output and "Permission denied" not in nft_output:
                    print_info(nft_output)
                else:
                    print_warning("  Cannot read nftables rules (requires root privileges)")
            
            # Check /proc/net/ip_tables_names (shows if iptables is being used)
            ip_tables = self.read_file("/proc/net/ip_tables_names")
            if ip_tables:
                print_status("Active iptables tables:")
                print_info(ip_tables)
                
        except Exception as e:
            print_warning(f"Error enumerating firewall: {e}")
    
    def _enum_dns(self):
        """Enumerate DNS configuration"""
        print_status("="*60)
        print_status("DNS Configuration")
        print_status("="*60)
        
        try:
            # Get resolv.conf
            resolv_conf = self.read_file("/etc/resolv.conf")
            if resolv_conf:
                print_info("DNS Resolvers (/etc/resolv.conf):")
                for line in resolv_conf.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        print_info(f"  {line}")
            
            # Get systemd-resolved configuration (if available)
            resolved_conf = self.read_file("/etc/systemd/resolved.conf")
            if resolved_conf:
                print_info("systemd-resolved Configuration:")
                for line in resolved_conf.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#') and '=' in line:
                        print_info(f"  {line}")
            
            # Get NetworkManager DNS configuration
            nm_conf = self.read_file("/etc/NetworkManager/NetworkManager.conf")
            if nm_conf:
                print_info("NetworkManager Configuration:")
                print_info(nm_conf)
            
            # Test DNS resolution
            print_status("DNS Resolution Test:")
            test_domains = ['google.com', 'github.com', 'microsoft.com']
            for domain in test_domains:
                dns_test = self.cmd_exec(f"getent hosts {domain} 2>/dev/null || host {domain} 2>/dev/null | head -1")
                if dns_test and dns_test.strip():
                    print_info(f"  {domain}: {dns_test.strip()}")
            
            # Get hosts file
            hosts_file = self.read_file("/etc/hosts")
            if hosts_file:
                print_status("Hosts File (/etc/hosts):")
                for line in hosts_file.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        print_info(f"  {line}")
                        
        except Exception as e:
            print_warning(f"Error enumerating DNS: {e}")
    
    def _enum_network_history(self):
        """Enumerate network connection history"""
        print_status("="*60)
        print_status("Network Connection History")
        print_status("="*60)
        
        try:
            # Check for connection logs in various locations
            log_files = [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/messages",
                "/var/log/syslog"
            ]
            
            print_status("Recent SSH Connections:")
            for log_file in log_files:
                if self.file_exist(log_file):
                    # Try to extract SSH connection attempts
                    ssh_logs = self.cmd_exec(f"grep -i 'ssh\\|connection' {log_file} 2>/dev/null | tail -20")
                    if ssh_logs:
                        print_info(f"From {log_file}:")
                        for line in ssh_logs.strip().split('\n'):
                            if line.strip():
                                print_info(f"  {line}")
                        break
            
            # Check for netstat history (if available in logs)
            print_status("Network Statistics:")
            netstat_history = self.cmd_exec("cat /proc/net/sockstat 2>/dev/null")
            if netstat_history:
                print_info(netstat_history)
            
            # Check for recent network activity in /proc
            print_status("Network Statistics from /proc:")
            snmp_stats = self.read_file("/proc/net/snmp")
            if snmp_stats:
                print_info("SNMP Statistics:")
                print_info(snmp_stats[:500])  # Limit output
            
            # Check for connection tracking (if available)
            if self.file_exist("/proc/net/ip_conntrack"):
                conntrack = self.cmd_exec("cat /proc/net/ip_conntrack 2>/dev/null | head -20")
                if conntrack:
                    print_status("Connection Tracking:")
                    print_info(conntrack)
            elif self.file_exist("/proc/net/nf_conntrack"):
                conntrack = self.cmd_exec("cat /proc/net/nf_conntrack 2>/dev/null | head -20")
                if conntrack:
                    print_status("Connection Tracking (nf_conntrack):")
                    print_info(conntrack)
                    
        except Exception as e:
            print_warning(f"Error enumerating network history: {e}")

