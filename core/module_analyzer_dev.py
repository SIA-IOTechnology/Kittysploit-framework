#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Analyzer for KittySploit
Provides dynamic analysis of modules for preview generation
"""

import re
import inspect
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ModuleAnalysis:
    """Module analysis result"""
    name: str
    type: str
    description: str
    target_info: str
    payload_info: str
    execution_steps: List[Dict[str, Any]]
    network_connections: List[Dict[str, str]]
    estimated_data_size: str
    estimated_time: str
    success_probability: str
    opsec_rating: str
    potential_impacts: List[str]
    module_characteristics: Dict[str, Any]

class ModuleAnalyzer:
    """Dynamic module analyzer for preview generation"""
    
    def __init__(self):
        """Initialize module analyzer"""
        self.logger = logger
        
        # Keywords for module type detection
        self.type_keywords = {
            'exploit': ['exploit', 'vulnerability', 'buffer_overflow', 'rce', 'lfi', 'rfi', 'sqli', 'xss'],
            'auxiliary': ['scan', 'enum', 'test', 'check', 'gather', 'brute', 'fuzz', 'proxy'],
            'listener': ['listener', 'handler', 'bind', 'reverse', 'payload'],
            'payload': ['payload', 'shell', 'meterpreter', 'stager', 'stage']
        }
        
        # Keywords for impact assessment
        self.impact_keywords = {
            'high': ['exploit', 'rce', 'buffer_overflow', 'privilege_escalation', 'root', 'admin'],
            'medium': ['lfi', 'rfi', 'sqli', 'xss', 'injection', 'bypass'],
            'low': ['scan', 'enum', 'test', 'check', 'gather', 'info', 'discovery']
        }
        
        # Keywords for opsec assessment
        self.opsec_keywords = {
            'high': ['stealth', 'evasion', 'bypass', 'encrypted', 'tunnel'],
            'medium': ['exploit', 'injection', 'payload'],
            'low': ['scan', 'brute', 'fuzz', 'test', 'enum', 'gather']
        }
        
        # Network protocol patterns
        self.protocol_patterns = {
            'http': ['http', 'web', 'www', 'apache', 'nginx', 'iis'],
            'https': ['https', 'ssl', 'tls', 'secure'],
            'ftp': ['ftp', 'file_transfer'],
            'ssh': ['ssh', 'secure_shell'],
            'smb': ['smb', 'samba', 'windows', 'netbios'],
            'tcp': ['tcp', 'socket', 'connection'],
            'udp': ['udp', 'dns', 'snmp']
        }
    
    def analyze_module(self, module) -> ModuleAnalysis:
        """
        Analyze a module and generate preview information
        
        Args:
            module: Module instance to analyze
            
        Returns:
            ModuleAnalysis: Complete analysis result
        """
        try:
            # Basic module information
            name = getattr(module, 'name', 'Unknown')
            description = getattr(module, 'description', 'No description available')
            
            # Determine module type
            module_type = self._determine_module_type(module, name, description)
            
            # Extract target information
            target_info = self._extract_target_info(module)
            
            # Extract payload information
            payload_info = self._extract_payload_info(module)
            
            # Generate execution steps
            execution_steps = self._generate_execution_steps(module, module_type, name)
            
            # Generate network connections
            network_connections = self._generate_network_connections(module, module_type, name)
            
            # Estimate resources
            data_size = self._estimate_data_size(module, module_type, name)
            execution_time = self._estimate_execution_time(module, module_type, name)
            
            # Assess success probability
            success_prob = self._assess_success_probability(module, module_type, name)
            
            # Assess opsec rating
            opsec_rating = self._assess_opsec_rating(module, module_type, name)
            
            # Assess potential impacts
            impacts = self._assess_potential_impacts(module, module_type, name)
            
            # Extract module characteristics
            characteristics = self._extract_module_characteristics(module)
            
            return ModuleAnalysis(
                name=name,
                type=module_type,
                description=description,
                target_info=target_info,
                payload_info=payload_info,
                execution_steps=execution_steps,
                network_connections=network_connections,
                estimated_data_size=data_size,
                estimated_time=execution_time,
                success_probability=success_prob,
                opsec_rating=opsec_rating,
                potential_impacts=impacts,
                module_characteristics=characteristics
            )
            
        except Exception as e:
            self.logger.error(f"Error analyzing module: {e}")
            return self._create_default_analysis(module)
    
    def _determine_module_type(self, module, name: str, description: str) -> str:
        """Determine module type based on name and description"""
        text_to_analyze = f"{name} {description}".lower()
        
        # Check for explicit type attribute
        if hasattr(module, 'type') and module.type:
            return module.type
        
        # Analyze based on keywords
        for module_type, keywords in self.type_keywords.items():
            if any(keyword in text_to_analyze for keyword in keywords):
                return module_type
        
        # Default to auxiliary if no clear match
        return 'auxiliary'
    
    def _extract_target_info(self, module) -> str:
        """Extract target information from module options"""
        target = "Unknown"
        port = ""
        
        # First try to get from options dictionary
        if hasattr(module, 'options'):
            # Look for target/host options
            target_options = ['target', 'host', 'rhost', 'rhosts', 'hostname', 'ip']
            for option_name, option in module.options.items():
                if any(target_opt in option_name.lower() for target_opt in target_options):
                    if hasattr(option, 'value') and option.value:
                        target = option.value
                        break
            
            # Look for port options
            port_options = ['port', 'rport', 'lport', 'target_port']
            for option_name, option in module.options.items():
                if any(port_opt in option_name.lower() for port_opt in port_options):
                    if hasattr(option, 'value') and option.value:
                        port = f":{option.value}"
                        break
        
        # If not found in options, try class attributes (for modules like proxy_test)
        if target == "Unknown":
            target_options = ['target', 'host', 'rhost', 'rhosts', 'hostname', 'ip']
            for attr_name in dir(module):
                # Skip methods and private attributes
                if attr_name.startswith('_') or callable(getattr(module, attr_name)):
                    continue
                # Check for exact match first, then partial match
                if attr_name.lower() in target_options:
                    attr_value = getattr(module, attr_name)
                    # Check if it's an option object with .value or direct value
                    if hasattr(attr_value, 'value') and attr_value.value:
                        target = attr_value.value
                        break
                    elif isinstance(attr_value, (str, int)) and attr_value:
                        target = str(attr_value)
                        break
            
            # Look for port options in class attributes
            if port == "":
                port_options = ['port', 'rport', 'lport', 'target_port']
                for attr_name in dir(module):
                    # Skip methods and private attributes
                    if attr_name.startswith('_') or callable(getattr(module, attr_name)):
                        continue
                    # Check for exact match first, then partial match
                    if attr_name.lower() in port_options:
                        attr_value = getattr(module, attr_name)
                        # Check if it's an option object with .value or direct value
                        if hasattr(attr_value, 'value') and attr_value.value:
                            port = f":{attr_value.value}"
                            break
                        elif isinstance(attr_value, (str, int)) and attr_value:
                            port = f":{attr_value}"
                            break
        
        return f"{target}{port}"
    
    def _extract_payload_info(self, module) -> str:
        """Extract payload information from module options"""
        payload = "No payload"
        
        # First try to get from options dictionary
        if hasattr(module, 'options'):
            payload_options = ['payload', 'shell', 'stager', 'stage', 'encoder']
            for option_name, option in module.options.items():
                if any(payload_opt in option_name.lower() for payload_opt in payload_options):
                    if hasattr(option, 'value') and option.value:
                        payload = option.value
                        break
        
        # If not found in options, try class attributes
        if payload == "No payload":
            payload_options = ['payload', 'shell', 'stager', 'stage', 'encoder']
            for attr_name in dir(module):
                # Skip methods and private attributes
                if attr_name.startswith('_') or callable(getattr(module, attr_name)):
                    continue
                # Check for exact match first, then partial match
                if attr_name.lower() in payload_options:
                    attr_value = getattr(module, attr_name)
                    # Check if it's an option object with .value or direct value
                    if hasattr(attr_value, 'value') and attr_value.value:
                        payload = attr_value.value
                        break
                    elif isinstance(attr_value, (str, int)) and attr_value:
                        payload = str(attr_value)
                        break
        
        return payload
    
    def _generate_execution_steps(self, module, module_type: str, name: str) -> List[Dict[str, Any]]:
        """Generate execution steps based on module analysis"""
        steps = []
        
        if module_type == 'exploit':
            steps = self._generate_exploit_steps(module, name)
        elif module_type == 'auxiliary':
            steps = self._generate_auxiliary_steps(module, name)
        elif module_type == 'listener':
            steps = self._generate_listener_steps(module, name)
        elif module_type == 'payload':
            steps = self._generate_payload_steps(module, name)
        else:
            steps = self._generate_generic_steps(module, name)
        
        return steps
    
    def _generate_exploit_steps(self, module, name: str) -> List[Dict[str, Any]]:
        """Generate steps for exploit modules"""
        steps = [
            {'description': 'Verify target reachability', 'completed': True},
            {'description': 'Check service version and vulnerabilities', 'completed': False}
        ]
        
        # Add specific steps based on exploit type
        if 'buffer_overflow' in name.lower():
            steps.extend([
                {'description': 'Craft buffer overflow payload', 'completed': False},
                {'description': 'Send malicious buffer', 'completed': False},
                {'description': 'Trigger buffer overflow', 'completed': False}
            ])
        elif 'sqli' in name.lower() or 'sql' in name.lower():
            steps.extend([
                {'description': 'Identify SQL injection point', 'completed': False},
                {'description': 'Craft SQL injection payload', 'completed': False},
                {'description': 'Execute SQL injection', 'completed': False}
            ])
        elif 'xss' in name.lower():
            steps.extend([
                {'description': 'Identify XSS vulnerability', 'completed': False},
                {'description': 'Craft XSS payload', 'completed': False},
                {'description': 'Execute XSS attack', 'completed': False}
            ])
        else:
            steps.extend([
                {'description': 'Craft exploit payload', 'completed': False},
                {'description': 'Send exploit payload', 'completed': False}
            ])
        
        steps.extend([
            {'description': 'Establish connection', 'completed': False},
            {'description': 'Inject payload stage', 'completed': False},
            {'description': 'Open interactive session', 'completed': False}
        ])
        
        return steps
    
    def _generate_auxiliary_steps(self, module, name: str) -> List[Dict[str, Any]]:
        """Generate steps for auxiliary modules"""
        steps = [
            {'description': 'Initialize auxiliary module', 'completed': True}
        ]
        
        # Add specific steps based on auxiliary type
        if 'scan' in name.lower():
            steps.extend([
                {'description': 'Configure scan parameters', 'completed': False},
                {'description': 'Perform target scanning', 'completed': False},
                {'description': 'Analyze scan results', 'completed': False}
            ])
        elif 'enum' in name.lower():
            steps.extend([
                {'description': 'Configure enumeration parameters', 'completed': False},
                {'description': 'Perform target enumeration', 'completed': False},
                {'description': 'Process enumeration data', 'completed': False}
            ])
        elif 'brute' in name.lower():
            steps.extend([
                {'description': 'Load wordlist', 'completed': False},
                {'description': 'Configure brute force parameters', 'completed': False},
                {'description': 'Execute brute force attack', 'completed': False}
            ])
        elif 'proxy' in name.lower():
            steps.extend([
                {'description': 'Configure proxy settings', 'completed': False},
                {'description': 'Test HTTP requests through proxy', 'completed': False},
                {'description': 'Test HTTPS requests through proxy', 'completed': False},
                {'description': 'Test TCP connections through proxy', 'completed': False}
            ])
        else:
            steps.extend([
                {'description': 'Configure module parameters', 'completed': False},
                {'description': 'Execute auxiliary function', 'completed': False}
            ])
        
        steps.extend([
            {'description': 'Process results', 'completed': False},
            {'description': 'Generate output', 'completed': False}
        ])
        
        return steps
    
    def _generate_listener_steps(self, module, name: str) -> List[Dict[str, Any]]:
        """Generate steps for listener modules"""
        return [
            {'description': 'Initialize listener', 'completed': True},
            {'description': 'Bind to specified port', 'completed': False},
            {'description': 'Wait for incoming connections', 'completed': False},
            {'description': 'Handle connection requests', 'completed': False},
            {'description': 'Establish secure channel', 'completed': False},
            {'description': 'Ready for payload delivery', 'completed': False}
        ]
    
    def _generate_payload_steps(self, module, name: str) -> List[Dict[str, Any]]:
        """Generate steps for payload modules"""
        return [
            {'description': 'Initialize payload', 'completed': True},
            {'description': 'Configure payload parameters', 'completed': False},
            {'description': 'Generate payload code', 'completed': False},
            {'description': 'Encode payload if needed', 'completed': False},
            {'description': 'Prepare for delivery', 'completed': False}
        ]
    
    def _generate_generic_steps(self, module, name: str) -> List[Dict[str, Any]]:
        """Generate generic steps for unknown module types"""
        return [
            {'description': 'Initialize module', 'completed': True},
            {'description': 'Configure module parameters', 'completed': False},
            {'description': 'Execute module function', 'completed': False},
            {'description': 'Process results', 'completed': False},
            {'description': 'Generate output', 'completed': False}
        ]
    
    def _generate_network_connections(self, module, module_type: str, name: str) -> List[Dict[str, str]]:
        """Generate network connection patterns"""
        connections = []
        
        if module_type == 'exploit':
            connections = [
                {'type': 'Service Connection', 'response': 'Service Response'},
                {'type': 'Exploit Payload', 'response': 'Shell Connection'},
                {'type': 'Payload Stage', 'response': 'Session Established'}
            ]
        elif module_type == 'listener':
            connections = [
                {'type': 'Bind to Port', 'response': 'Port Bound'},
                {'type': 'Listen for Connections', 'response': 'Connection Received'},
                {'type': 'Payload Delivery', 'response': 'Session Established'}
            ]
        elif module_type == 'auxiliary':
            if 'proxy' in name.lower():
                connections = [
                    {'type': 'HTTP Request via Proxy', 'response': 'HTTP Response'},
                    {'type': 'HTTPS Request via Proxy', 'response': 'HTTPS Response'},
                    {'type': 'TCP Connection via Proxy', 'response': 'TCP Response'}
                ]
            elif 'scan' in name.lower():
                connections = [
                    {'type': 'Port Scan Request', 'response': 'Port Scan Response'},
                    {'type': 'Service Detection', 'response': 'Service Banner'},
                    {'type': 'Vulnerability Check', 'response': 'Vulnerability Report'}
                ]
            elif 'brute' in name.lower():
                connections = [
                    {'type': 'Authentication Attempt', 'response': 'Auth Response'},
                    {'type': 'Credential Test', 'response': 'Success/Failure'},
                    {'type': 'Result Collection', 'response': 'Brute Force Report'}
                ]
            else:
                connections = [
                    {'type': 'Module Request', 'response': 'Module Response'},
                    {'type': 'Data Collection', 'response': 'Data Received'}
                ]
        else:
            connections = [
                {'type': 'Module Request', 'response': 'Module Response'}
            ]
        
        return connections
    
    def _estimate_data_size(self, module, module_type: str, name: str) -> str:
        """Estimate data size based on module analysis"""
        if module_type == 'auxiliary':
            if 'proxy' in name.lower():
                return '0.8 KB'
            elif 'scan' in name.lower():
                return '1.2 KB'
            elif 'brute' in name.lower():
                return '2.5 KB'
            else:
                return '1.5 KB'
        elif module_type == 'listener':
            return '0.1 KB'
        elif module_type == 'exploit':
            if 'buffer_overflow' in name.lower():
                return '3.5 KB'
            elif 'sqli' in name.lower():
                return '1.8 KB'
            else:
                return '2.3 KB'
        else:
            return '2.0 KB'
    
    def _estimate_execution_time(self, module, module_type: str, name: str) -> str:
        """Estimate execution time based on module analysis"""
        if module_type == 'auxiliary':
            if 'proxy' in name.lower():
                return '3-8 seconds'
            elif 'scan' in name.lower():
                return '10-30 seconds'
            elif 'brute' in name.lower():
                return '30-300 seconds'
            else:
                return '5-15 seconds'
        elif module_type == 'listener':
            return 'Continuous'
        elif module_type == 'exploit':
            if 'buffer_overflow' in name.lower():
                return '20-45 seconds'
            else:
                return '15-30 seconds'
        else:
            return '10-20 seconds'
    
    def _assess_success_probability(self, module, module_type: str, name: str) -> str:
        """Assess success probability based on module analysis"""
        if module_type == 'auxiliary':
            if 'proxy' in name.lower():
                return '95%'
            elif 'scan' in name.lower():
                return '90%'
            elif 'brute' in name.lower():
                return '60%'
            else:
                return '85%'
        elif module_type == 'listener':
            return '98%'
        elif module_type == 'exploit':
            if 'buffer_overflow' in name.lower():
                return '75%'
            elif 'sqli' in name.lower():
                return '85%'
            else:
                return '94%'
        else:
            return '90%'
    
    def _assess_opsec_rating(self, module, module_type: str, name: str) -> str:
        """Assess operational security rating"""
        text_to_analyze = name.lower()
        
        # Check for high opsec keywords
        if any(keyword in text_to_analyze for keyword in self.opsec_keywords['high']):
            return 'High'
        elif any(keyword in text_to_analyze for keyword in self.opsec_keywords['low']):
            return 'Low'
        else:
            return 'Medium'
    
    def _assess_potential_impacts(self, module, module_type: str, name: str) -> List[str]:
        """Assess potential impacts based on module analysis"""
        impacts = []
        text_to_analyze = name.lower()
        
        if module_type == 'exploit':
            impacts.extend([
                "Target service may crash (10% probability)",
                "IDS/IPS may detect this attack",
                "Windows Event Logs will record connection",
                "Network traffic will be visible to monitoring"
            ])
        elif module_type == 'listener':
            impacts.extend([
                "Incoming connections will be logged",
                "Port binding may be detected by port scanners",
                "Network monitoring may detect listener activity"
            ])
        elif module_type == 'auxiliary':
            if 'proxy' in text_to_analyze:
                impacts.extend([
                    "Proxy requests will be logged",
                    "Target server logs will record requests",
                    "Network monitoring may detect proxy usage",
                    "No direct impact on target services"
                ])
            elif 'brute' in text_to_analyze:
                impacts.extend([
                    "Authentication attempts will be logged",
                    "Account lockout may occur",
                    "Intrusion detection systems may trigger",
                    "High network traffic volume"
                ])
            else:
                impacts.extend([
                    "Scanning activity may be detected",
                    "Target logs may record connection attempts",
                    "Network monitoring may flag unusual traffic",
                    "No direct impact on target services"
                ])
        else:
            impacts.extend([
                "Module activity may be logged",
                "Network monitoring may detect activity",
                "No direct impact on target services"
            ])
        
        return impacts
    
    def _extract_module_characteristics(self, module) -> Dict[str, Any]:
        """Extract additional module characteristics"""
        characteristics = {
            'has_options': hasattr(module, 'options') and len(module.options) > 0,
            'option_count': len(module.options) if hasattr(module, 'options') else 0,
            'requires_root': getattr(module, 'requires_root', False),
            'has_run_method': hasattr(module, 'run') and callable(getattr(module, 'run')),
            'module_path': getattr(module, '__module__', 'Unknown')
        }
        
        return characteristics
    
    def _create_default_analysis(self, module) -> ModuleAnalysis:
        """Create default analysis when module analysis fails"""
        return ModuleAnalysis(
            name=getattr(module, 'name', 'Unknown'),
            type='auxiliary',
            description='No description available',
            target_info='Unknown',
            payload_info='No payload',
            execution_steps=[
                {'description': 'Initialize module', 'completed': True},
                {'description': 'Execute module function', 'completed': False}
            ],
            network_connections=[
                {'type': 'Module Request', 'response': 'Module Response'}
            ],
            estimated_data_size='2.0 KB',
            estimated_time='10-20 seconds',
            success_probability='90%',
            opsec_rating='Medium',
            potential_impacts=['Module activity may be logged'],
            module_characteristics={}
        )
