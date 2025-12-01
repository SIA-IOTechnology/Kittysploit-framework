#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Portal Client - Handles communication with KittySploit Portal SaaS
"""

import requests
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.output_handler import print_info, print_success, print_error, print_warning


class PortalClient:
    """Client for communicating with KittySploit Portal SaaS"""
    
    def __init__(self, server_url: str, api_key: str):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'KittySploit-Framework/1.0'
        })
        self.connected = False
        self.user_info = None
    
    def test_connection(self) -> bool:
        """Test connection to Portal"""
        try:
            response = self.session.get(f"{self.server_url}/api/v1/status", timeout=10)
            
            if response.status_code == 200:
                self.connected = True
                return True
            else:
                print_error(f"Connection failed: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print_error(f"Connection error: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get connection status"""
        return {
            'connected': self.connected,
            'server': self.server_url,
            'user': self.user_info.get('username') if self.user_info else None,
            'last_sync': getattr(self, 'last_sync', 'Never')
        }
    
    def get_user_info(self) -> Dict:
        """Get user information"""
        try:
            if not self.connected:
                self.test_connection()
            
            response = self.session.get(f"{self.server_url}/api/v1/user", timeout=10)
            
            if response.status_code == 200:
                self.user_info = response.json()
                return self.user_info
            else:
                print_error(f"Failed to get user info: {response.status_code}")
                return {}
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error getting user info: {e}")
            return {}
    
    def get_projects(self) -> List[Dict]:
        """Get available projects"""
        try:
            if not self.connected:
                self.test_connection()
            
            response = self.session.get(f"{self.server_url}/api/v1/projects", timeout=10)
            
            if response.status_code == 200:
                return response.json().get('projects', [])
            else:
                print_error(f"Failed to get projects: {response.status_code}")
                return []
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error getting projects: {e}")
            return []
    
    def submit_finding(self, finding_data: Dict) -> Optional[Dict]:
        """Submit a finding to Portal"""
        try:
            if not self.connected:
                self.test_connection()
            
            # Prepare finding data
            payload = {
                'title': finding_data['title'],
                'description': finding_data.get('description', ''),
                'severity': finding_data['severity'],
                'project_id': finding_data.get('project_id'),
                'tags': finding_data.get('tags', []),
                'submitted_at': datetime.utcnow().isoformat(),
                'source': 'kittysploit-framework'
            }
            
            response = self.session.post(
                f"{self.server_url}/api/v1/findings",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 201:
                return response.json()
            else:
                print_error(f"Failed to submit finding: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error submitting finding: {e}")
            return None
    
    def sync_workspace_up(self, workspace_name: str) -> bool:
        """Sync workspace data up to Portal"""
        try:
            if not self.connected:
                self.test_connection()
            
            # Get workspace data from framework
            workspace_data = self._get_workspace_data(workspace_name)
            
            if not workspace_data:
                print_warning(f"No data found for workspace '{workspace_name}'")
                return False
            
            # Upload to Portal
            payload = {
                'workspace_name': workspace_name,
                'data': workspace_data,
                'sync_type': 'upload',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            response = self.session.post(
                f"{self.server_url}/api/v1/workspaces/sync",
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                self.last_sync = datetime.utcnow().isoformat()
                print_success(f"Workspace '{workspace_name}' uploaded successfully")
                return True
            else:
                print_error(f"Failed to upload workspace: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error uploading workspace: {e}")
            return False
    
    def sync_workspace_down(self, workspace_name: str) -> bool:
        """Sync workspace data down from Portal"""
        try:
            if not self.connected:
                self.test_connection()
            
            # Download from Portal
            response = self.session.get(
                f"{self.server_url}/api/v1/workspaces/{workspace_name}",
                timeout=60
            )
            
            if response.status_code == 200:
                workspace_data = response.json()
                
                # Apply data to local workspace
                if self._apply_workspace_data(workspace_name, workspace_data):
                    self.last_sync = datetime.utcnow().isoformat()
                    print_success(f"Workspace '{workspace_name}' downloaded successfully")
                    return True
                else:
                    print_error("Failed to apply workspace data locally")
                    return False
            else:
                print_error(f"Failed to download workspace: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error downloading workspace: {e}")
            return False
    
    def _get_workspace_data(self, workspace_name: str) -> Dict:
        """Get workspace data from framework"""
        try:
            # This would integrate with the framework to get workspace data
            # For now, return mock data
            return {
                'name': workspace_name,
                'hosts': [],
                'services': [],
                'vulnerabilities': [],
                'credentials': [],
                'notes': [],
                'loot': [],
                'tasks': [],
                'modules': [],
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            print_error(f"Error getting workspace data: {e}")
            return {}
    
    def _apply_workspace_data(self, workspace_name: str, workspace_data: Dict) -> bool:
        """Apply workspace data to local framework"""
        try:
            # This would integrate with the framework to apply workspace data
            # For now, just return success
            print_info(f"Applying workspace data for '{workspace_name}'...")
            return True
            
        except Exception as e:
            print_error(f"Error applying workspace data: {e}")
            return False
    
    def get_findings(self, project_id: str = None, limit: int = 100) -> List[Dict]:
        """Get findings from Portal"""
        try:
            if not self.connected:
                self.test_connection()
            
            params = {'limit': limit}
            if project_id:
                params['project_id'] = project_id
            
            response = self.session.get(
                f"{self.server_url}/api/v1/findings",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json().get('findings', [])
            else:
                print_error(f"Failed to get findings: {response.status_code}")
                return []
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error getting findings: {e}")
            return []
    
    def create_project(self, project_data: Dict) -> Optional[Dict]:
        """Create a new project in Portal"""
        try:
            if not self.connected:
                self.test_connection()
            
            response = self.session.post(
                f"{self.server_url}/api/v1/projects",
                json=project_data,
                timeout=30
            )
            
            if response.status_code == 201:
                return response.json()
            else:
                print_error(f"Failed to create project: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error creating project: {e}")
            return None
    
    def get_collaborative_findings(self, project_id: str = None) -> List[Dict]:
        """Get collaborative findings from other users"""
        try:
            if not self.connected:
                self.test_connection()
            
            params = {'collaborative': True}
            if project_id:
                params['project_id'] = project_id
            
            response = self.session.get(
                f"{self.server_url}/api/v1/findings",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json().get('findings', [])
            else:
                print_error(f"Failed to get collaborative findings: {response.status_code}")
                return []
                
        except requests.exceptions.RequestException as e:
            print_error(f"Error getting collaborative findings: {e}")
            return []
