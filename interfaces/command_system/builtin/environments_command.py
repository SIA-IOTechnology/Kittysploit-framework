#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Environments command implementation for managing Docker environments
"""

import os
import docker
from datetime import datetime
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_status

class EnvironmentsCommand(BaseCommand):
    """Command to manage Docker environments"""
    
    @property
    def name(self) -> str:
        return "environments"
    
    @property
    def description(self) -> str:
        return "Manage Docker environments (list, stop, restart)"
    
    @property
    def usage(self) -> str:
        return "environments [list|stop|restart|info|help] [container_name|container_id]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to manage Docker environments created by KittySploit modules.

Subcommands:
    list                    List all Docker environments (default)
    stop <name|id>          Stop a specific environment
    stop all                Stop all environments
    restart <name|id>       Restart a specific environment
    info <name|id>          Show detailed information about an environment
    help                    Show this help message

Examples:
    environments                # List all environments
    environments list           # List all environments
    environments stop dvwa      # Stop environment named 'dvwa'
    environments stop all       # Stop all environments
    environments restart dvwa   # Restart environment named 'dvwa'
    environments info dvwa     # Show info about environment 'dvwa'
    environments help           # Show this help message
        """
    
    def _get_docker_client(self):
        """Get Docker client with proper error handling"""
        try:
            # Try to use docker.from_env() first
            try:
                client = docker.from_env()
                client.ping()
                return client
            except:
                # On Windows, fall back to named pipe
                if os.name == 'nt':
                    client = docker.DockerClient(base_url='npipe:////./pipe/docker_engine')
                    client.ping()
                    return client
                raise
        except docker.errors.DockerException as e:
            print_error(f"Cannot connect to Docker: {str(e)}")
            if os.name == 'nt':
                print_error("Make sure Docker Desktop is running.")
            else:
                print_error("Make sure Docker daemon is running.")
            return None
        except Exception as e:
            print_error(f"Error connecting to Docker: {str(e)}")
            return None
    
    def _get_kittysploit_containers(self, client):
        """Get all containers that appear to be KittySploit environments"""
        try:
            all_containers = client.containers.list(all=True)
            kittysploit_containers = []
            
            for container in all_containers:
                # Check if container name starts with kittysploit_ or matches known patterns
                name = container.name
                if (name.startswith('kittysploit_') or 
                    'dvwa' in name.lower() or
                    'metasploitable' in name.lower() or
                    'webgoat' in name.lower()):
                    kittysploit_containers.append(container)
            
            return kittysploit_containers
        except Exception as e:
            print_error(f"Error listing containers: {str(e)}")
            return []
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the environments command"""
        if not args:
            # Default to list if no arguments
            return self._list_environments()
        
        subcommand = args[0].lower()
        
        try:
            if subcommand == "list":
                return self._list_environments()
            elif subcommand == "stop":
                if len(args) < 2:
                    print_error("Container name or ID required for stop command")
                    print_info("Usage: environments stop <container_name|container_id|all>")
                    return False
                return self._stop_environment(args[1])
            elif subcommand == "restart":
                if len(args) < 2:
                    print_error("Container name or ID required for restart command")
                    print_info("Usage: environments restart <container_name|container_id>")
                    return False
                return self._restart_environment(args[1])
            elif subcommand == "info":
                if len(args) < 2:
                    print_error("Container name or ID required for info command")
                    print_info("Usage: environments info <container_name|container_id>")
                    return False
                return self._show_info(args[1])
            elif subcommand == "help":
                return self._show_help()
            else:
                print_error(f"Unknown subcommand: {subcommand}")
                print_info("Available subcommands: list, stop, restart, info, help")
                return False
                
        except Exception as e:
            print_error(f"Error executing environments command: {str(e)}")
            return False
    
    def _list_environments(self) -> bool:
        """List all Docker environments"""
        client = self._get_docker_client()
        if not client:
            return False
        
        containers = self._get_kittysploit_containers(client)
        
        if not containers:
            print_info("No Docker environments found.")
            return True
        
        # Print header
        print_info()
        print_info("=" * 100)
        print_info(f"{'Name':<30} {'ID':<15} {'Status':<15} {'Image':<30} {'Ports':<20}")
        print_info("=" * 100)
        
        for container in containers:
            try:
                container.reload()
                name = container.name
                container_id = container.id[:12]
                status = container.status
                
                # Get image name
                image = container.image.tags[0] if container.image.tags else container.image.id[:12]
                
                # Get exposed ports
                ports = []
                if container.attrs.get('NetworkSettings', {}).get('Ports'):
                    for container_port, host_ports in container.attrs['NetworkSettings']['Ports'].items():
                        if host_ports:
                            for host_port in host_ports:
                                ports.append(f"{host_port['HostIp']}:{host_port['HostPort']}->{container_port}")
                    ports_str = ', '.join(ports[:2])  # Show first 2 ports
                    if len(ports) > 2:
                        ports_str += f" (+{len(ports)-2} more)"
                else:
                    ports_str = "N/A"
                
                # Color code status
                if status == "running":
                    status_str = f"\033[92m{status}\033[0m"
                elif status == "exited":
                    status_str = f"\033[91m{status}\033[0m"
                else:
                    status_str = f"\033[93m{status}\033[0m"
                
                print_info(f"{name:<30} {container_id:<15} {status_str:<25} {image:<30} {ports_str:<20}")
                
            except Exception as e:
                print_warning(f"Error getting info for container: {str(e)}")
                continue
        
        print_info("=" * 100)
        print_info("")
        
        return True
    
    def _stop_environment(self, identifier: str) -> bool:
        """Stop a Docker environment"""
        client = self._get_docker_client()
        if not client:
            return False
        
        if identifier.lower() == "all":
            containers = self._get_kittysploit_containers(client)
            if not containers:
                print_info("No environments to stop.")
                return True
            
            stopped_count = 0
            for container in containers:
                try:
                    if container.status == "running":
                        print_status(f"Stopping {container.name}...")
                        container.stop()
                        print_success(f"Stopped {container.name}")
                        stopped_count += 1
                    else:
                        print_info(f"{container.name} is already stopped")
                except Exception as e:
                    print_error(f"Error stopping {container.name}: {str(e)}")
            
            if stopped_count > 0:
                print_success(f"Stopped {stopped_count} environment(s)")
            return True
        
        # Stop specific container
        try:
            container = client.containers.get(identifier)
            
            # Verify it's a KittySploit container
            if container.name not in [c.name for c in self._get_kittysploit_containers(client)]:
                print_warning(f"Container '{identifier}' does not appear to be a KittySploit environment")
                response = input("Do you want to stop it anyway? (y/N): ")
                if response.lower() != 'y':
                    print_info("Operation cancelled.")
                    return False
            
            if container.status != "running":
                print_warning(f"Container {container.name} is not running (status: {container.status})")
                return False
            
            print_status(f"Stopping {container.name}...")
            container.stop()
            print_success(f"Stopped {container.name} successfully")
            return True
            
        except docker.errors.NotFound:
            print_error(f"Container '{identifier}' not found")
            return False
        except Exception as e:
            print_error(f"Error stopping container: {str(e)}")
            return False
    
    def _restart_environment(self, identifier: str) -> bool:
        """Restart a Docker environment"""
        client = self._get_docker_client()
        if not client:
            return False
        
        try:
            container = client.containers.get(identifier)
            
            # Verify it's a KittySploit container
            if container.name not in [c.name for c in self._get_kittysploit_containers(client)]:
                print_warning(f"Container '{identifier}' does not appear to be a KittySploit environment")
                response = input("Do you want to restart it anyway? (y/N): ")
                if response.lower() != 'y':
                    print_info("Operation cancelled.")
                    return False
            
            print_status(f"Restarting {container.name}...")
            container.restart()
            print_success(f"Restarted {container.name} successfully")
            return True
            
        except docker.errors.NotFound:
            print_error(f"Container '{identifier}' not found")
            return False
        except Exception as e:
            print_error(f"Error restarting container: {str(e)}")
            return False
    
    def _show_info(self, identifier: str) -> bool:
        """Show detailed information about an environment"""
        client = self._get_docker_client()
        if not client:
            return False
        
        try:
            container = client.containers.get(identifier)
            container.reload()
            
            print_info("")
            print_status("=" * 80)
            print_status(f"Environment Information: {container.name}")
            print_status("=" * 80)
            
            print_info(f"Name:        {container.name}")
            print_info(f"ID:          {container.id}")
            print_info(f"Status:      {container.status}")
            print_info(f"Image:       {container.image.tags[0] if container.image.tags else container.image.id}")
            
            # Created time
            created = container.attrs.get('Created', '')
            if created:
                try:
                    # Parse ISO format datetime string
                    created_str = created.replace('T', ' ').split('.')[0]
                    print_info(f"Created:     {created_str}")
                except:
                    print_info(f"Created:     {created}")
            
            # Ports
            print_info("\nPorts:")
            if container.attrs.get('NetworkSettings', {}).get('Ports'):
                for container_port, host_ports in container.attrs['NetworkSettings']['Ports'].items():
                    if host_ports:
                        for host_port in host_ports:
                            print_info(f"  {host_port['HostIp']}:{host_port['HostPort']} -> {container_port}")
                    else:
                        print_info(f"  {container_port} (not mapped)")
            else:
                print_info("  No ports exposed")
            
            # IP Address
            networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
            if networks:
                print_info("\nNetwork:")
                for network_name, network_config in networks.items():
                    ip = network_config.get('IPAddress', 'N/A')
                    print_info(f"  Network: {network_name}")
                    print_info(f"  IP:      {ip}")
            
            print_status("=" * 80)
            print_info("")
            
            return True
            
        except docker.errors.NotFound:
            print_error(f"Container '{identifier}' not found")
            return False
        except Exception as e:
            print_error(f"Error getting container info: {str(e)}")
            return False
    
    def _show_help(self) -> bool:
        """Show help message"""
        print_info(self.help_text)
        return True

