#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS Lambda Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module enumerates AWS Lambda functions, their configurations, and code.
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate AWS Lambda functions"""
    
    __info__ = {
        "name": "Enumerate AWS Lambda",
        "description": "Enumerate Lambda functions, configurations, and code",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    list_functions = OptBool(True, "List all Lambda functions", False)
    get_configurations = OptBool(True, "Get function configurations", False)
    get_code = OptBool(False, "Download function code (can be large)", False)
    get_environment = OptBool(True, "Get environment variables", False)
    check_triggers = OptBool(True, "Check function triggers and events", False)
    output_file = OptString("", "Output file to save results (JSON format)", False)
    
    def run(self):
        """Run the Lambda enumeration"""
        try:
            results = {}
            
            print_info("Starting AWS Lambda enumeration...")
            print_info("=" * 80)
            
            # List functions
            if self.list_functions.value:
                print_info("\n[1] Listing Lambda functions...")
                functions = self._list_functions()
                if functions:
                    results['functions'] = functions
                    print_success(f"Found {len(functions)} Lambda functions")
                    
                    for func in functions:
                        name = func.get('FunctionName', 'Unknown')
                        runtime = func.get('Runtime', 'Unknown')
                        handler = func.get('Handler', 'Unknown')
                        memory = func.get('MemorySize', 0)
                        timeout = func.get('Timeout', 0)
                        last_modified = func.get('LastModified', 'Unknown')
                        
                        print_info(f"\n  - {name}")
                        print_info(f"    Runtime: {runtime}, Handler: {handler}")
                        print_info(f"    Memory: {memory} MB, Timeout: {timeout}s")
                        print_info(f"    Last Modified: {last_modified}")
                else:
                    print_info("No Lambda functions found or access denied")
            
            # Get detailed configurations
            if self.get_configurations.value and results.get('functions'):
                print_info("\n[2] Getting function configurations...")
                for func in results['functions']:
                    func_name = func.get('FunctionName')
                    if not func_name:
                        continue
                    
                    print_info(f"  Getting configuration for: {func_name}")
                    config = self._get_function_configuration(func_name)
                    if config:
                        func['configuration'] = config
                        
                        # Show interesting details
                        env_vars = config.get('Environment', {}).get('Variables', {})
                        if env_vars and self.get_environment.value:
                            print_warning(f"    ⚠️  Environment variables found:")
                            for key, value in list(env_vars.items())[:5]:
                                # Mask sensitive values
                                if 'secret' in key.lower() or 'password' in key.lower() or 'key' in key.lower():
                                    masked = value[:4] + "*" * (len(value) - 8) + value[-4:] if len(value) > 8 else "*" * len(value)
                                    print_info(f"      {key}: {masked}")
                                else:
                                    print_info(f"      {key}: {value}")
                            if len(env_vars) > 5:
                                print_info(f"      ... and {len(env_vars) - 5} more")
            
            # Get function code
            if self.get_code.value and results.get('functions'):
                print_info("\n[3] Downloading function code...")
                for func in results['functions'][:5]:  # Limit to first 5
                    func_name = func.get('FunctionName')
                    if not func_name:
                        continue
                    
                    print_info(f"  Downloading code for: {func_name}")
                    code_info = self._get_function_code(func_name)
                    if code_info:
                        func['code'] = code_info
                        print_info(f"    Code size: {code_info.get('CodeSize', 0)} bytes")
            
            # Check triggers
            if self.check_triggers.value and results.get('functions'):
                print_info("\n[4] Checking function triggers...")
                for func in results['functions']:
                    func_name = func.get('FunctionName')
                    if not func_name:
                        continue
                    
                    triggers = self._get_function_triggers(func_name)
                    if triggers:
                        func['triggers'] = triggers
                        if triggers:
                            print_info(f"  {func_name}: {len(triggers)} trigger(s)")
                            for trigger in triggers[:3]:
                                print_info(f"    - {trigger.get('Type', 'Unknown')}: {trigger.get('SourceArn', 'Unknown')}")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            print_success(f"Found {len(results.get('functions', []))} Lambda functions")
            
            # Check for sensitive data
            sensitive_found = False
            for func in results.get('functions', []):
                env_vars = func.get('configuration', {}).get('Environment', {}).get('Variables', {})
                if env_vars:
                    for key in env_vars.keys():
                        if any(sensitive in key.lower() for sensitive in ['secret', 'password', 'key', 'token', 'credential']):
                            sensitive_found = True
                            break
            
            if sensitive_found:
                print_warning("⚠️  Functions with potentially sensitive environment variables found!")
            
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
    
    def _list_functions(self):
        """List all Lambda functions"""
        cmd = "aws lambda list-functions 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Functions', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    lambda_client = boto3.client('lambda')
    response = lambda_client.list_functions()
    print(json.dumps(response.get('Functions', [])))
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
    
    def _get_function_configuration(self, function_name):
        """Get Lambda function configuration"""
        cmd = f"aws lambda get-function-configuration --function-name {function_name} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                return json.loads(result)
            except:
                pass
        
        # Try Python boto3
        python_cmd = f"""
python3 -c "
import boto3, json
try:
    lambda_client = boto3.client('lambda')
    response = lambda_client.get_function_configuration(FunctionName='{function_name}')
    print(json.dumps(response))
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
    
    def _get_function_code(self, function_name):
        """Get Lambda function code location"""
        cmd = f"aws lambda get-function --function-name {function_name} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                code = data.get('Code', {})
                return {
                    'Location': code.get('Location'),
                    'RepositoryType': code.get('RepositoryType'),
                    'CodeSize': code.get('CodeSize', 0)
                }
            except:
                pass
        return None
    
    def _get_function_triggers(self, function_name):
        """Get Lambda function triggers"""
        # Get event source mappings
        cmd = f"aws lambda list-event-source-mappings --function-name {function_name} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        triggers = []
        if result:
            try:
                data = json.loads(result)
                mappings = data.get('EventSourceMappings', [])
                for mapping in mappings:
                    triggers.append({
                        'Type': 'EventSourceMapping',
                        'SourceArn': mapping.get('EventSourceArn'),
                        'State': mapping.get('State')
                    })
            except:
                pass
        
        # Also check for API Gateway triggers (requires listing API Gateway)
        # This is simplified - full implementation would query API Gateway
        
        return triggers

