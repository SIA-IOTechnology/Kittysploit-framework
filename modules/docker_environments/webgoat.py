#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

class Module(DockerEnvironment):
    __info__ = {
        'name': 'WebGoat Environment',
        'description': 'OWASP WebGoat - Learning platform for web application security testing',
        'author': 'KittySploit Team',
        'references': [
            'https://github.com/WebGoat/WebGoat',
            'https://owasp.org/www-project-webgoat/',
            'https://hub.docker.com/r/webgoat/goatandwolf'
        ]
    }
    
    # Options du module
    image_name = OptString("webgoat/goatandwolf:latest", "Docker image name to use", True)
    container_name = OptString("kittysploit_webgoat", "Container name", True)
    
    # Ports
    webgoat_port = OptPort(8080, "WebGoat port (mapped to container port 8080)", True)
    webwolf_port = OptPort(9090, "WebWolf port (mapped to container port 9090)", True)
    
    ready_timeout = OptInteger(180, "Timeout in seconds for WebGoat to be ready", True)
    
    def expose_ports(self):
        """Configure exposed ports for WebGoat"""
        self.exposed_ports = {
            "8080/tcp": ('127.0.0.1', int(self.webgoat_port)),
            "9090/tcp": ('127.0.0.1', int(self.webwolf_port))
        }
        # Set environment variable for WebGoat
        self.environment_vars = {
            'WEBGOAT_PORT': '8080'
        }
    
    def on_environment_ready(self):
        """Display WebGoat access information"""
        if not self.print_container_overview():
            return False
        
        print_success("=== WebGoat started successfully ===")
        
        print_status("Access Information:")
        print_info("=" * 60)
        print_info(f"WebGoat: http://127.0.0.1:{self.webgoat_port}/WebGoat")
        print_info(f"WebWolf: http://127.0.0.1:{self.webwolf_port}/WebWolf")
        
        print_status("Default Credentials:")
        print_info("  Login: guest / guest")        
        return True
