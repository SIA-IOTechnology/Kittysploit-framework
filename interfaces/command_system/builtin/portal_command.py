#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Portal command implementation - Push results to KittySploit SaaS (app.kittysploit.com)
"""

import argparse
import json
import os
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class PortalCommand(BaseCommand):
    """Command to push results to KittySploit SaaS portal"""
    
    @property
    def name(self) -> str:
        return "portal"
    
    @property
    def description(self) -> str:
        return "Push results (hosts, vulnerabilities, etc.) to KittySploit SaaS portal"
    
    @property
    def usage(self) -> str:
        return "portal [--api-key <key>] [--push-hosts] [--push-vulns] [--push-all] [--status] [--config]"
    
    @property
    def help_text(self) -> str:
        return """
Push results to KittySploit SaaS portal (app.kittysploit.com)

This command allows you to synchronize your local results (hosts, vulnerabilities, etc.)
with the KittySploit SaaS portal for centralized management and reporting.

Subcommands:
    --api-key <key>     Set or update your API key
    --push-hosts        Push all hosts to the portal
    --push-vulns        Push all vulnerabilities to the portal
    --push-all          Push all hosts and vulnerabilities
    --status            Check connection status and API key validity
    --config            Show current portal configuration

Examples:
    portal --api-key your_api_key_here        # Set API key
    portal --status                           # Check connection
    portal --push-hosts                      # Push all hosts
    portal --push-vulns                      # Push all vulnerabilities
    portal --push-all                        # Push everything
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
        self.portal_url = "https://app.kittysploit.com"
        self.api_key = None
        self.config_file = os.path.join(
            os.path.expanduser("~"),
            ".kittysploit",
            "portal_config.json"
        )
        self._load_config()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Push results to KittySploit SaaS portal",
            add_help=True
        )
        
        parser.add_argument('--api-key', dest='api_key', help='Set or update API key')
        parser.add_argument('--push-hosts', action='store_true', help='Push all hosts to portal')
        parser.add_argument('--push-vulns', action='store_true', help='Push all vulnerabilities to portal')
        parser.add_argument('--push-all', action='store_true', help='Push all hosts and vulnerabilities')
        parser.add_argument('--status', action='store_true', help='Check connection status and API key')
        parser.add_argument('--config', action='store_true', help='Show current configuration')
        
        return parser
    
    def _load_config(self):
        """Load portal configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key')
        except Exception as e:
            # Silently fail - config file might not exist yet
            pass
    
    def _save_config(self):
        """Save portal configuration to file"""
        try:
            # Create directory if it doesn't exist
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir, mode=0o700)
            
            config = {
                'api_key': self.api_key,
                'portal_url': self.portal_url,
                'updated_at': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Set restrictive permissions
            os.chmod(self.config_file, 0o600)
        except Exception as e:
            print_error(f"Error saving configuration: {e}")
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the portal command"""
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        # Check for help requests
        if args and args[0].lower() in ['help', '--help', '-h']:
            self.parser.print_help()
            return True
        
        try:
            # Handle different actions
            if parsed_args.api_key:
                return self._set_api_key(parsed_args.api_key)
            elif parsed_args.status:
                return self._check_status()
            elif parsed_args.config:
                return self._show_config()
            elif parsed_args.push_hosts:
                return self._push_hosts()
            elif parsed_args.push_vulns:
                return self._push_vulnerabilities()
            elif parsed_args.push_all:
                return self._push_all()
            else:
                # Default: show help
                self.parser.print_help()
                return True
                
        except Exception as e:
            print_error(f"Error executing portal command: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _set_api_key(self, api_key: str) -> bool:
        """Set or update API key"""
        if not api_key or len(api_key.strip()) == 0:
            print_error("API key cannot be empty")
            return False
        
        self.api_key = api_key.strip()
        self._save_config()
        print_success("API key saved successfully")
        print_info("Testing connection...")
        return self._check_status()
    
    def _show_config(self) -> bool:
        """Show current configuration"""
        print_info("Portal Configuration")
        print_info("=" * 80)
        print_info(f"Portal URL: {self.portal_url}")
        if self.api_key:
            # Show only first 8 and last 4 characters for security
            masked_key = f"{self.api_key[:8]}...{self.api_key[-4:]}" if len(self.api_key) > 12 else "***"
            print_info(f"API Key: {masked_key}")
        else:
            print_warning("API Key: Not set")
        print_info(f"Config File: {self.config_file}")
        print_info("=" * 80)
        return True
    
    def _check_status(self) -> bool:
        """Check connection status and API key validity"""
        if not self.api_key:
            print_error("API key not set. Use 'portal --api-key <key>' to set it")
            return False
        
        print_info("Checking connection to portal...")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
                'User-Agent': 'KittySploit-Framework/1.0.0'
            }
            
            # Test connection with a simple status endpoint
            response = requests.get(
                f"{self.portal_url}/api/v1/status",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print_success("Connection successful!")
                try:
                    data = response.json()
                    if 'user' in data:
                        print_info(f"Authenticated as: {data.get('user', {}).get('email', 'Unknown')}")
                    if 'workspace' in data:
                        print_info(f"Workspace: {data.get('workspace', {}).get('name', 'Unknown')}")
                except:
                    pass
                return True
            elif response.status_code == 401:
                print_error("Authentication failed. Please check your API key")
                return False
            else:
                print_warning(f"Unexpected response: {response.status_code}")
                print_info(f"Response: {response.text[:200]}")
                return False
                
        except requests.exceptions.ConnectionError:
            print_error("Failed to connect to portal. Please check your internet connection")
            return False
        except requests.exceptions.Timeout:
            print_error("Connection timeout. Please try again later")
            return False
        except Exception as e:
            print_error(f"Error checking status: {e}")
            return False
    
    def _get_db_session(self):
        """Get database session"""
        if not hasattr(self.framework, 'get_db_session'):
            return None
        return self.framework.get_db_session()
    
    def _push_hosts(self) -> bool:
        """Push all hosts to the portal"""
        if not self.api_key:
            print_error("API key not set. Use 'portal --api-key <key>' to set it")
            return False
        
        session = self._get_db_session()
        if not session:
            print_error("Database not available")
            return False
        
        try:
            from core.models.models import Host, Workspace
            
            # Get current workspace
            current_workspace = self.framework.workspace_manager.get_current_workspace() if hasattr(self.framework, 'workspace_manager') else None
            if not current_workspace:
                print_error("No workspace found")
                return False
            
            # Get all hosts from current workspace
            hosts = session.query(Host).filter(Host.workspace_id == current_workspace.id).all()
            
            if not hosts:
                print_warning("No hosts found in current workspace")
                return True
            
            print_info(f"Found {len(hosts)} hosts to push...")
            
            # Prepare hosts data
            hosts_data = []
            for host in hosts:
                host_dict = host.to_dict()
                # Get services and vulnerabilities for this host
                if hasattr(host, 'services'):
                    host_dict['services'] = [s.to_dict() for s in host.services]
                if hasattr(host, 'vulnerabilities'):
                    host_dict['vulnerabilities'] = [v.to_dict() for v in host.vulnerabilities]
                hosts_data.append(host_dict)
            
            # Push to portal
            return self._send_to_portal('hosts', hosts_data)
            
        except Exception as e:
            print_error(f"Error pushing hosts: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _push_vulnerabilities(self) -> bool:
        """Push all vulnerabilities to the portal"""
        if not self.api_key:
            print_error("API key not set. Use 'portal --api-key <key>' to set it")
            return False
        
        session = self._get_db_session()
        if not session:
            print_error("Database not available")
            return False
        
        try:
            from core.models.models import Vulnerability, Host, host_vulnerabilities
            
            # Get current workspace
            current_workspace = self.framework.workspace_manager.get_current_workspace() if hasattr(self.framework, 'workspace_manager') else None
            if not current_workspace:
                print_error("No workspace found")
                return False
            
            # Get all vulnerabilities associated with hosts in current workspace
            vulnerabilities = session.query(Vulnerability).join(
                host_vulnerabilities
            ).join(
                Host
            ).filter(
                Host.workspace_id == current_workspace.id
            ).distinct().all()
            
            if not vulnerabilities:
                print_warning("No vulnerabilities found in current workspace")
                return True
            
            print_info(f"Found {len(vulnerabilities)} vulnerabilities to push...")
            
            # Prepare vulnerabilities data
            vulns_data = []
            for vuln in vulnerabilities:
                vuln_dict = vuln.to_dict()
                # Get associated hosts
                if hasattr(vuln, 'hosts'):
                    vuln_dict['hosts'] = [h.to_dict() for h in vuln.hosts]
                vulns_data.append(vuln_dict)
            
            # Push to portal
            return self._send_to_portal('vulnerabilities', vulns_data)
            
        except Exception as e:
            print_error(f"Error pushing vulnerabilities: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _push_all(self) -> bool:
        """Push all hosts and vulnerabilities"""
        print_info("Pushing all data to portal...")
        print_info("")
        
        hosts_success = self._push_hosts()
        print_info("")
        vulns_success = self._push_vulnerabilities()
        
        if hosts_success and vulns_success:
            print_success("All data pushed successfully!")
            return True
        else:
            print_warning("Some data may not have been pushed successfully")
            return False
    
    def _send_to_portal(self, endpoint: str, data: List[Dict]) -> bool:
        """Send data to portal API"""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
                'User-Agent': 'KittySploit-Framework/1.0.0'
            }
            
            payload = {
                'data': data,
                'workspace': self.framework.workspace_manager.get_current_workspace().name if hasattr(self.framework, 'workspace_manager') else 'default',
                'timestamp': datetime.now().isoformat(),
                'framework_version': self.framework.version if hasattr(self.framework, 'version') else '1.0.0'
            }
            
            print_info(f"Sending {len(data)} items to portal...")
            
            response = requests.post(
                f"{self.portal_url}/api/v1/{endpoint}/sync",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                print_success(f"Successfully pushed {len(data)} {endpoint} to portal")
                try:
                    result = response.json()
                    if 'message' in result:
                        print_info(result['message'])
                    if 'created' in result:
                        print_info(f"Created: {result['created']}")
                    if 'updated' in result:
                        print_info(f"Updated: {result['updated']}")
                except:
                    pass
                return True
            elif response.status_code == 401:
                print_error("Authentication failed. Please check your API key")
                return False
            elif response.status_code == 400:
                print_error(f"Bad request: {response.text[:200]}")
                return False
            else:
                print_error(f"Failed to push data: {response.status_code}")
                print_info(f"Response: {response.text[:200]}")
                return False
                
        except requests.exceptions.ConnectionError:
            print_error("Failed to connect to portal. Please check your internet connection")
            return False
        except requests.exceptions.Timeout:
            print_error("Connection timeout. Please try again later")
            return False
        except Exception as e:
            print_error(f"Error sending data to portal: {e}")
            return False

