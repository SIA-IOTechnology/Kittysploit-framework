#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

class Module(DockerEnvironment):
    __info__ = {
        'name': 'Metasploitable Environment',
        'description': 'Metasploitable Linux - Intentionally vulnerable Linux distribution for penetration testing',
        'author': 'KittySploit Team',
        'references': [
            'https://github.com/rapid7/metasploitable3',
            'https://sourceforge.net/projects/metasploitable/',
            'https://hub.docker.com/r/tleemcjr/metasploitable2'
        ]
    }
    
    # Options du module
    image_name = OptString("tleemcjr/metasploitable2:latest", "Docker image name to use", True)
    container_name = OptString("kittysploit_metasploitable", "Container name", True)
    
    # Ports principaux (les autres utilisent les valeurs par défaut du conteneur)
    ssh_port = OptPort(2222, "SSH port (mapped to container port 22)", True)
    web_port = OptPort(80, "Web port (mapped to container port 80)", True)
    ftp_port = OptPort(21, "FTP port (mapped to container port 21)", True)
    mysql_port = OptPort(3306, "MySQL port (mapped to container port 3306)", True)
    
    ready_timeout = OptInteger(180, "Timeout in seconds for Metasploitable to be ready", True)
    
    def expose_ports(self):
        """Configure all exposed ports for Metasploitable"""
        self.exposed_ports = {
            # Ports principaux (configurables) - bound to 127.0.0.1
            "22/tcp": ('127.0.0.1', int(self.ssh_port)),
            "80/tcp": ('127.0.0.1', int(self.web_port)),
            "21/tcp": ('127.0.0.1', int(self.ftp_port)),
            "3306/tcp": ('127.0.0.1', int(self.mysql_port)),
            # Ports supplémentaires (valeurs par défaut du conteneur) - bound to 127.0.0.1
            "23/tcp": ('127.0.0.1', 23), "25/tcp": ('127.0.0.1', 25),
            "53/tcp": ('127.0.0.1', 53), "53/udp": ('127.0.0.1', 53),
            "111/tcp": ('127.0.0.1', 111), "111/udp": ('127.0.0.1', 111),
            "139/tcp": ('127.0.0.1', 139), "445/tcp": ('127.0.0.1', 445),
            "993/tcp": ('127.0.0.1', 993), "995/tcp": ('127.0.0.1', 995),
            "1723/tcp": ('127.0.0.1', 1723), "5900/tcp": ('127.0.0.1', 5900),
            "8080/tcp": ('127.0.0.1', 8080)
        }
    
    def on_environment_ready(self):
        """Display Metasploitable access information"""
        if not self.print_container_overview():
            return False
        
        print_status("Main Services:")
        print_info("=" * 60)
        print_info(f"SSH:     ssh msfadmin@127.0.0.1 -p {self.ssh_port}")
        print_info(f"Web:     http://127.0.0.1:{self.web_port}")
        print_info(f"FTP:     ftp://127.0.0.1:{self.ftp_port}")
        print_info(f"MySQL:   mysql -h 127.0.0.1 -P {self.mysql_port} -u root -p")
        
        print_status("Default Credentials:")
        print_info("  SSH:     msfadmin / msfadmin")
        print_info("  FTP:     msfadmin / msfadmin")
        print_info("  MySQL:   root / root")
        print_info("  Telnet:  msfadmin / msfadmin")
        print_info("  VNC:     No password")
        
        print_status("Additional Services (default ports):")
        print_info("  Telnet:  23, SMTP: 25, DNS: 53, RPC: 111")
        print_info("  SMB:     139, 445, IMAPS: 993, POP3S: 995")
        print_info("  PPTP:    1723, VNC: 5900, Web Alt: 8080")
        
        return True
