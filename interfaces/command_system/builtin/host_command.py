#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Host command implementation for managing hosts in the database
"""

import argparse
import json
from datetime import datetime
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table

class HostCommand(BaseCommand):
    """Command to manage hosts in the database"""
    
    @property
    def name(self) -> str:
        return "host"
    
    @property
    def description(self) -> str:
        return "Manage hosts in the database"
    
    @property
    def usage(self) -> str:
        return "hosts [--add] [--list] [--delete] [--info] [--search] [--update] [--import] [--export]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to manage hosts in the database, similar to Metasploit's
hosts command. You can add, list, delete, search, and update host information.

Options:
    --add, -a <host>     Add a new host to the database
    --list, -l           List all hosts in the database
    --delete, -d <id>    Delete a host by ID
    --info, -i <id>      Show detailed information about a host
    --search, -s <term>  Search hosts by IP, hostname, or OS
    --update, -u <id>    Update host information
    --import <file>      Import hosts from JSON file
    --export <file>      Export hosts to JSON file
    --limit <num>        Limit number of results (default: 50)
    --json               Output in JSON format

Examples:
    hosts --add 192.168.1.100                    # Add a host
    hosts --list                                  # List all hosts
    hosts --search "Windows"                      # Search for Windows hosts
    hosts --info 1                                # Show info for host ID 1
    hosts --delete 1                              # Delete host ID 1
    hosts --export hosts.json                     # Export all hosts
    hosts --import hosts.json                     # Import hosts from file
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Manage hosts in the database",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  hosts --add 192.168.1.100                    # Add a host
  hosts --list                                  # List all hosts
  hosts --search "Windows"                      # Search for Windows hosts
  hosts --info 1                                # Show info for host ID 1
  hosts --delete 1                              # Delete host ID 1
  hosts --export hosts.json                     # Export all hosts
  hosts --import hosts.json                     # Import hosts from file
            """
        )
        
        # Action arguments
        parser.add_argument("--add", "-a", dest="add_host", help="Add a new host (IP address)")
        parser.add_argument("--list", "-l", action="store_true", help="List all hosts")
        parser.add_argument("--delete", "-d", dest="delete_id", type=int, help="Delete host by ID")
        parser.add_argument("--info", "-i", dest="info_id", type=int, help="Show detailed host information")
        parser.add_argument("--search", "-s", dest="search_term", help="Search hosts")
        parser.add_argument("--update", "-u", dest="update_id", type=int, help="Update host information")
        parser.add_argument("--import", dest="import_file", help="Import hosts from JSON file")
        parser.add_argument("--export", dest="export_file", help="Export hosts to JSON file")
        
        # Filter arguments
        parser.add_argument("--limit", type=int, default=50, help="Limit number of results")
        parser.add_argument("--json", action="store_true", help="Output in JSON format")
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the hosts command"""
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        try:
            # Get database session
            if not hasattr(self.framework, 'get_db_session'):
                print_error("Database not available")
                return False
            
            session = self.framework.get_db_session()
            
            if parsed_args.add_host:
                return self._add_host(session, parsed_args.add_host)
            elif parsed_args.list:
                return self._list_hosts(session, parsed_args)
            elif parsed_args.delete_id:
                return self._delete_host(session, parsed_args.delete_id)
            elif parsed_args.info_id:
                return self._show_host_info(session, parsed_args.info_id)
            elif parsed_args.search_term:
                return self._search_hosts(session, parsed_args)
            elif parsed_args.update_id:
                return self._update_host(session, parsed_args.update_id)
            elif parsed_args.import_file:
                return self._import_hosts(session, parsed_args.import_file)
            elif parsed_args.export_file:
                return self._export_hosts(session, parsed_args.export_file)
            else:
                # Default: list hosts
                return self._list_hosts(session, parsed_args)
                    
        except Exception as e:
            print_error(f"Error executing hosts command: {str(e)}")
            return False
    
    def _add_host(self, session, host_ip):
        """Add a new host to the database"""
        try:
            from core.models.models import Host, Workspace
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Check if host already exists
            existing_host = session.query(Host).filter(
                Host.workspace_id == workspace.id,
                Host.address == host_ip
            ).first()
            
            if existing_host:
                print_warning(f"Host {host_ip} already exists (ID: {existing_host.id})")
                return True
            
            # Create new host
            new_host = Host(
                workspace_id=workspace.id,
                address=host_ip,
                hostname="",
                os="Unknown",
                os_version="",
                mac="",
                status="up"
            )
            
            session.add(new_host)
            session.commit()
            
            print_success(f"Added host {host_ip} (ID: {new_host.id})")
            return True
            
        except Exception as e:
            print_error(f"Error adding host: {str(e)}")
            return False
    
    def _list_hosts(self, session, parsed_args):
        """List hosts in the database"""
        try:
            from core.models.models import Host, Workspace
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Query hosts
            query = session.query(Host).filter(Host.workspace_id == workspace.id)
            hosts = query.limit(parsed_args.limit).all()
            
            if not hosts:
                print_info("No hosts found in database")
                return True
            
            if parsed_args.json:
                # JSON output
                hosts_data = []
                for host in hosts:
                    hosts_data.append({
                        'id': host.id,
                        'address': host.address,
                        'hostname': host.hostname,
                        'os': host.os,
                        'os_version': host.os_version,
                        'status': host.status,
                        'created_at': host.created_at.isoformat() if host.created_at else None
                    })
                print(json.dumps(hosts_data, indent=2))
            else:
                # Table output
                headers = ["ID", "IP Address", "Hostname", "OS", "Status", "Last Seen"]
                rows = []
                
                for host in hosts:
                    os_info = f"{host.os} {host.os_version}".strip()
                    created_at = host.created_at.strftime("%Y-%m-%d %H:%M") if host.created_at else "Never"
                    
                    rows.append([
                        str(host.id),
                        host.address,
                        host.hostname or "Unknown",
                        os_info or "Unknown",
                        host.status,
                        created_at
                    ])
                
                print_table(headers, rows)
                print_info(f"Found {len(hosts)} hosts")
            
            return True
            
        except Exception as e:
            print_error(f"Error listing hosts: {str(e)}")
            return False
    
    def _delete_host(self, session, host_id):
        """Delete a host from the database"""
        try:
            from core.models.models import Host
            
            host = session.query(Host).filter(Host.id == host_id).first()
            if not host:
                print_error(f"Host with ID {host_id} not found")
                return False
            
            session.delete(host)
            session.commit()
            
            print_success(f"Deleted host {host.address} (ID: {host_id})")
            return True
            
        except Exception as e:
            print_error(f"Error deleting host: {str(e)}")
            return False
    
    def _show_host_info(self, session, host_id):
        """Show detailed information about a host"""
        try:
            from core.models.models import Host, Service, Vulnerability
            
            host = session.query(Host).filter(Host.id == host_id).first()
            if not host:
                print_error(f"Host with ID {host_id} not found")
                return False
            
            print_info(f"Host Information - ID: {host_id}")
            print_info("=" * 50)
            print_info(f"IP Address: {host.address}")
            print_info(f"Hostname: {host.hostname or 'Unknown'}")
            print_info(f"OS: {host.os} {host.os_version}".strip() or "Unknown")
            print_info(f"MAC Address: {host.mac or 'Unknown'}")
            print_info(f"Status: {host.status}")
            print_info(f"Last Seen: {host.created_at.strftime('%Y-%m-%d %H:%M:%S') if host.created_at else 'Never'}")
            print_info(f"Created: {host.created_at.strftime('%Y-%m-%d %H:%M:%S') if host.created_at else 'Unknown'}")
            
            # Show services
            services = session.query(Service).filter(Service.host_id == host_id).all()
            if services:
                print_info(f"\nServices ({len(services)}):")
                for service in services:
                    print_info(f"  {service.port}/{service.protocol} - {service.service_name} ({service.state})")
            
            # Show vulnerabilities
            vulnerabilities = session.query(Vulnerability).filter(Vulnerability.host_id == host_id).all()
            if vulnerabilities:
                print_info(f"\nVulnerabilities ({len(vulnerabilities)}):")
                for vuln in vulnerabilities:
                    print_info(f"  {vuln.name} - {vuln.severity}")
            
            return True
            
        except Exception as e:
            print_error(f"Error showing host info: {str(e)}")
            return False
    
    def _search_hosts(self, session, parsed_args):
        """Search hosts by various criteria"""
        try:
            from core.models.models import Host, Workspace
            from sqlalchemy import or_
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Build search query
            search_term = parsed_args.search_term.lower()
            query = session.query(Host).filter(
                Host.workspace_id == workspace.id,
                or_(
                    Host.address.contains(search_term),
                    Host.hostname.contains(search_term),
                    Host.os.contains(search_term),
                    Host.os_version.contains(search_term)
                )
            )
            
            hosts = query.limit(parsed_args.limit).all()
            
            if not hosts:
                print_info(f"No hosts found matching '{parsed_args.search_term}'")
                return True
            
            if parsed_args.json:
                # JSON output
                hosts_data = []
                for host in hosts:
                    hosts_data.append({
                        'id': host.id,
                        'address': host.address,
                        'hostname': host.hostname,
                        'os': host.os,
                        'os_version': host.os_version,
                        'status': host.status,
                        'created_at': host.created_at.isoformat() if host.created_at else None
                    })
                print(json.dumps(hosts_data, indent=2))
            else:
                # Table output
                headers = ["ID", "IP Address", "Hostname", "OS", "Status", "Last Seen"]
                rows = []
                
                for host in hosts:
                    os_info = f"{host.os} {host.os_version}".strip()
                    created_at = host.created_at.strftime("%Y-%m-%d %H:%M") if host.created_at else "Never"
                    
                    rows.append([
                        str(host.id),
                        host.address,
                        host.hostname or "Unknown",
                        os_info or "Unknown",
                        host.status,
                        created_at
                    ])
                
                print_table(headers, rows)
                print_info(f"Found {len(hosts)} hosts matching '{parsed_args.search_term}'")
            
            return True
            
        except Exception as e:
            print_error(f"Error searching hosts: {str(e)}")
            return False
    
    def _update_host(self, session, host_id):
        """Update host information (interactive)"""
        try:
            from core.models.models import Host
            
            host = session.query(Host).filter(Host.id == host_id).first()
            if not host:
                print_error(f"Host with ID {host_id} not found")
                return False
            
            print_info(f"Updating host {host.address} (ID: {host_id})")
            print_info("Press Enter to keep current value")
            
            # Update hostname
            new_hostname = input(f"Hostname [{host.hostname or ''}]: ").strip()
            if new_hostname:
                host.hostname = new_hostname
            
            # Update OS
            new_os = input(f"OS Name [{host.os or ''}]: ").strip()
            if new_os:
                host.os = new_os
            
            new_os_version = input(f"OS Version [{host.os_version or ''}]: ").strip()
            if new_os_version:
                host.os_version = new_os_version
            
            # Update MAC
            new_mac = input(f"MAC Address [{host.mac or ''}]: ").strip()
            if new_mac:
                host.mac = new_mac
            
            # Update status
            new_status = input(f"Status [{host.status}]: ").strip()
            if new_status:
                host.status = new_status
            
            session.commit()
            print_success(f"Updated host {host.address}")
            return True
            
        except Exception as e:
            print_error(f"Error updating host: {str(e)}")
            return False
    
    def _import_hosts(self, session, filename):
        """Import hosts from JSON file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                hosts_data = json.load(f)
            
            imported_count = 0
            for host_data in hosts_data:
                if self._add_host_from_data(session, host_data):
                    imported_count += 1
            
            print_success(f"Imported {imported_count} hosts from {filename}")
            return True
            
        except Exception as e:
            print_error(f"Error importing hosts: {str(e)}")
            return False
    
    def _export_hosts(self, session, filename):
        """Export hosts to JSON file"""
        try:
            from core.models.models import Host, Workspace
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                print_error("No workspace found")
                return False
            
            # Query all hosts
            hosts = session.query(Host).filter(Host.workspace_id == workspace.id).all()
            
            # Prepare export data
            hosts_data = []
            for host in hosts:
                hosts_data.append({
                    'id': host.id,
                    'address': host.address,
                    'hostname': host.hostname,
                    'os': host.os,
                    'os_version': host.os_version,
                    'mac': host.mac,
                    'status': host.status,
                    'created_at': host.created_at.isoformat() if host.created_at else None,
                    'created_at': host.created_at.isoformat() if host.created_at else None
                })
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(hosts_data, f, indent=2, ensure_ascii=False)
            
            print_success(f"Exported {len(hosts_data)} hosts to {filename}")
            return True
            
        except Exception as e:
            print_error(f"Error exporting hosts: {str(e)}")
            return False
    
    def _add_host_from_data(self, session, host_data):
        """Add host from imported data"""
        try:
            from core.models.models import Host, Workspace
            
            # Get current workspace
            workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not workspace:
                return False
            
            # Check if host already exists
            existing_host = session.query(Host).filter(
                Host.workspace_id == workspace.id,
                Host.address == host_data.get('address')
            ).first()
            
            if existing_host:
                return False  # Skip existing hosts
            
            # Create new host
            new_host = Host(
                workspace_id=workspace.id,
                address=host_data.get('address', ''),
                hostname=host_data.get('hostname', ''),
                os=host_data.get('os', 'Unknown'),
                os_version=host_data.get('os_version', ''),
                mac=host_data.get('mac', ''),
                status=host_data.get('status', 'alive')
            )
            
            session.add(new_host)
            session.commit()
            return True
            
        except Exception as e:
            print_error(f"Error adding host from data: {str(e)}")
            return False
