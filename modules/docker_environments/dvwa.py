#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

class Module(DockerEnvironment):
    __info__ = {
        'name': 'DVWA - Damn Vulnerable Web Application',
        'description': 'Start a Docker environment containing DVWA for security web tests',
        'author': 'KittySploit Team',
        'references': [
            'https://github.com/digininja/DVWA',
            'https://hub.docker.com/r/vulnerables/web-dvwa/'
        ]
    }
    
    # Options du module
    host_port = OptPort(80, "Local port to expose DVWA", True)
    image_name = OptString("vulnerables/web-dvwa:latest", "Docker image name/tag/ID to use (or name for built image)", True)
    container_name = OptString("kittysploit_dvwa", "Container name", True)
    
    def on_environment_ready(self):
        if not self.print_container_overview():
            return False
        
        print_success("=== DVWA started successfully ===")
        print_success(f"Access DVWA via: http://127.0.0.1:{self.host_port}/")
        print_success("Default credentials: admin / password")
        return True
