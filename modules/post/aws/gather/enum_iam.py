#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS IAM Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module enumerates IAM users, roles, policies, and permissions.
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate AWS IAM users, roles, and policies"""
    
    __info__ = {
        "name": "Enumerate AWS IAM",
        "description": "Enumerate IAM users, roles, groups, and policies",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    enum_users = OptBool(True, "Enumerate IAM users", False)
    enum_roles = OptBool(True, "Enumerate IAM roles", False)
    enum_groups = OptBool(True, "Enumerate IAM groups", False)
    enum_policies = OptBool(True, "Enumerate IAM policies", False)
    enum_attached_policies = OptBool(True, "Enumerate attached policies for users/roles", False)
    check_permissions = OptBool(True, "Check current user permissions", False)
    output_file = OptString("", "Output file to save results (JSON format)", False)
    
    def run(self):
        """Run the IAM enumeration"""
        try:
            results = {}
            
            print_info("Starting AWS IAM enumeration...")
            print_info("=" * 80)
            
            # Check current identity
            if self.check_permissions.value:
                print_info("\n[1] Checking current IAM identity...")
                identity = self._get_caller_identity()
                if identity:
                    results['identity'] = identity
                    print_success(f"Current identity: {identity.get('Arn', 'Unknown')}")
                    print_info(f"  User ID: {identity.get('UserId', 'Unknown')}")
                    print_info(f"  Account: {identity.get('Account', 'Unknown')}")
                else:
                    print_warning("Could not retrieve IAM identity")
            
            # Enumerate users
            if self.enum_users.value:
                print_info("\n[2] Enumerating IAM users...")
                users = self._enum_users()
                if users:
                    results['users'] = users
                    print_success(f"Found {len(users)} IAM users")
                    for user in users[:10]:  # Show first 10
                        print_info(f"  - {user.get('UserName', 'Unknown')} ({user.get('UserId', 'Unknown')})")
                    if len(users) > 10:
                        print_info(f"  ... and {len(users) - 10} more")
                else:
                    print_info("No users found or access denied")
            
            # Enumerate roles
            if self.enum_roles.value:
                print_info("\n[3] Enumerating IAM roles...")
                roles = self._enum_roles()
                if roles:
                    results['roles'] = roles
                    print_success(f"Found {len(roles)} IAM roles")
                    for role in roles[:10]:  # Show first 10
                        print_info(f"  - {role.get('RoleName', 'Unknown')} ({role.get('RoleId', 'Unknown')})")
                    if len(roles) > 10:
                        print_info(f"  ... and {len(roles) - 10} more")
                else:
                    print_info("No roles found or access denied")
            
            # Enumerate groups
            if self.enum_groups.value:
                print_info("\n[4] Enumerating IAM groups...")
                groups = self._enum_groups()
                if groups:
                    results['groups'] = groups
                    print_success(f"Found {len(groups)} IAM groups")
                    for group in groups:
                        print_info(f"  - {group.get('GroupName', 'Unknown')}")
                else:
                    print_info("No groups found or access denied")
            
            # Enumerate policies
            if self.enum_policies.value:
                print_info("\n[5] Enumerating IAM policies...")
                policies = self._enum_policies()
                if policies:
                    results['policies'] = policies
                    print_success(f"Found {len(policies)} IAM policies")
                    for policy in policies[:10]:  # Show first 10
                        print_info(f"  - {policy.get('PolicyName', 'Unknown')} ({policy.get('Arn', 'Unknown')})")
                    if len(policies) > 10:
                        print_info(f"  ... and {len(policies) - 10} more")
                else:
                    print_info("No policies found or access denied")
            
            # Enumerate attached policies
            if self.enum_attached_policies.value and results.get('users'):
                print_info("\n[6] Enumerating attached policies for users...")
                for user in results['users'][:5]:  # Limit to first 5 users
                    username = user.get('UserName')
                    if username:
                        attached = self._get_user_policies(username)
                        if attached:
                            user['attached_policies'] = attached
                            print_info(f"  {username}: {len(attached)} attached policies")
            
            if self.enum_attached_policies.value and results.get('roles'):
                print_info("\n[7] Enumerating attached policies for roles...")
                for role in results['roles'][:5]:  # Limit to first 5 roles
                    role_name = role.get('RoleName')
                    if role_name:
                        attached = self._get_role_policies(role_name)
                        if attached:
                            role['attached_policies'] = attached
                            print_info(f"  {role_name}: {len(attached)} attached policies")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            print_success(f"Enumerated:")
            print_info(f"  - Users: {len(results.get('users', []))}")
            print_info(f"  - Roles: {len(results.get('roles', []))}")
            print_info(f"  - Groups: {len(results.get('groups', []))}")
            print_info(f"  - Policies: {len(results.get('policies', []))}")
            
            # Save to file if requested
            if self.output_file.value:
                try:
                    with open(self.output_file.value, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    print_success(f"Results saved to {self.output_file.value}")
                except Exception as e:
                    print_error(f"Failed to save results: {e}")
            
            return True
            
        except Exception as e:
            print_error(f"Error during enumeration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _get_caller_identity(self):
        """Get current IAM identity"""
        cmd = "aws sts get-caller-identity 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                return json.loads(result)
            except:
                # Try Python boto3
                python_cmd = """
python3 -c "
import boto3, json
try:
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print(json.dumps(identity))
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
    
    def _enum_users(self):
        """Enumerate IAM users"""
        cmd = "aws iam list-users 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Users', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    iam = boto3.client('iam')
    response = iam.list_users()
    print(json.dumps(response.get('Users', [])))
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
        return []
    
    def _enum_roles(self):
        """Enumerate IAM roles"""
        cmd = "aws iam list-roles 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Roles', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    iam = boto3.client('iam')
    response = iam.list_roles()
    print(json.dumps(response.get('Roles', [])))
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
        return []
    
    def _enum_groups(self):
        """Enumerate IAM groups"""
        cmd = "aws iam list-groups 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Groups', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    iam = boto3.client('iam')
    response = iam.list_groups()
    print(json.dumps(response.get('Groups', [])))
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
        return []
    
    def _enum_policies(self):
        """Enumerate IAM policies"""
        cmd = "aws iam list-policies --scope Local 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Policies', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    iam = boto3.client('iam')
    response = iam.list_policies(Scope='Local')
    print(json.dumps(response.get('Policies', [])))
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
        return []
    
    def _get_user_policies(self, username):
        """Get attached policies for a user"""
        cmd = f"aws iam list-attached-user-policies --user-name {username} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('AttachedPolicies', [])
            except:
                pass
        return []
    
    def _get_role_policies(self, role_name):
        """Get attached policies for a role"""
        cmd = f"aws iam list-attached-role-policies --role-name {role_name} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('AttachedPolicies', [])
            except:
                pass
        return []


