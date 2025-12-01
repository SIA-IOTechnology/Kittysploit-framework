#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS SQS Shell Implementation
This shell handles command execution via AWS SQS queues
"""

import time
import json
import base64
import threading
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

class AWSSQSShell(BaseShell):
    """AWS SQS Shell - executes commands via AWS SQS queues"""
    
    def __init__(self, session_id: str, session_type: str = "aws_sqs", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.sqs_client = None
        self.command_queue_url = None
        self.response_queue_url = None
        self.poll_interval = 2
        self.visibility_timeout = 30
        self.max_messages = 1
        self.use_base64 = True
        self.message_attributes = True
        
        # Response storage
        self.response_cache = {}  # {command_id: {'output': str, 'status': int, 'error': str, 'timestamp': float}}
        self.response_lock = threading.Lock()
        self.command_timeout = 60  # Timeout for waiting for response
        
        # Initialize from session data
        self._init_from_session()
    
    def _init_from_session(self):
        """Initialize shell from session data"""
        try:
            if not self.framework or not hasattr(self.framework, 'session_manager'):
                return
            
            session = self.framework.session_manager.get_session(self.session_id)
            if not session:
                return
            
            # Get connection data from session
            session_data = session.data if hasattr(session, 'data') else {}
            
            # Try to get SQS client from listener first (preferred method)
            if hasattr(self.framework, 'active_listeners'):
                for listener_id, listener in self.framework.active_listeners.items():
                    # Check if listener has this session
                    if hasattr(listener, '_session_connections'):
                        if self.session_id in listener._session_connections:
                            connection_data = listener._session_connections[self.session_id]
                            if isinstance(connection_data, dict):
                                # Get SQS client from listener
                                if hasattr(listener, 'sqs_client') and listener.sqs_client:
                                    self.sqs_client = listener.sqs_client
                                    self.command_queue_url = connection_data.get('command_queue_url', '')
                                    self.response_queue_url = connection_data.get('response_queue_url', '')
                                    self.poll_interval = connection_data.get('poll_interval', 2)
                                    self.visibility_timeout = connection_data.get('visibility_timeout', 30)
                                    self.max_messages = connection_data.get('max_messages', 1)
                                    self.use_base64 = connection_data.get('use_base64', True)
                                    self.message_attributes = connection_data.get('message_attributes', True)
                                    return
            
            # Fallback: get from session data and create new client
            if 'command_queue_url' in session_data:
                self.command_queue_url = session_data.get('command_queue_url', '')
                self.response_queue_url = session_data.get('response_queue_url', '')
                
                # Try to create SQS client
                if BOTO3_AVAILABLE:
                    try:
                        region = session_data.get('aws_region', 'us-east-1')
                        self.sqs_client = boto3.client('sqs', region_name=region)
                        self.poll_interval = session_data.get('poll_interval', 2)
                        self.visibility_timeout = session_data.get('visibility_timeout', 30)
                        self.max_messages = session_data.get('max_messages', 1)
                        self.use_base64 = session_data.get('use_base64', True)
                        self.message_attributes = session_data.get('message_attributes', True)
                    except Exception as e:
                        print_error(f"Failed to create SQS client: {e}")
            
        except Exception as e:
            print_error(f"Error initializing AWS SQS shell: {e}")
    
    @property
    def shell_name(self) -> str:
        return "aws_sqs"
    
    @property
    def prompt_template(self) -> str:
        return "aws-sqs@{hostname}:{directory}$ "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.prompt_template.format(
            username=self.username,
            hostname=self.hostname or "aws-sqs",
            directory=self.current_directory
        )
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command via AWS SQS"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        if not BOTO3_AVAILABLE:
            return {'output': '', 'status': 1, 'error': 'boto3 library not installed'}
        
        if not self.sqs_client or not self.command_queue_url:
            return {'output': '', 'status': 1, 'error': 'AWS SQS not configured. Check listener configuration.'}
        
        # Add to history
        self.add_to_history(command)
        
        try:
            # Generate command ID
            command_id = f"cmd_{int(time.time() * 1000)}_{len(self.command_history)}"
            
            # Prepare message
            message_data = {
                'command_id': command_id,
                'command': command,
                'timestamp': time.time()
            }
            
            message_body = json.dumps(message_data)
            
            # Encode if base64
            if self.use_base64:
                message_body = base64.b64encode(message_body.encode('utf-8')).decode('utf-8')
            
            # Prepare message attributes if enabled
            message_attributes = {}
            if self.message_attributes:
                message_attributes = {
                    'CommandID': {
                        'StringValue': command_id,
                        'DataType': 'String'
                    },
                    'Timestamp': {
                        'StringValue': str(time.time()),
                        'DataType': 'Number'
                    }
                }
            
            # Send command to queue
            response = self.sqs_client.send_message(
                QueueUrl=self.command_queue_url,
                MessageBody=message_body,
                MessageAttributes=message_attributes if message_attributes else None
            )
            
            print_info(f"Command sent: {command} (ID: {command_id})")
            
            # Wait for response
            start_time = time.time()
            while time.time() - start_time < self.command_timeout:
                # Check response cache
                with self.response_lock:
                    if command_id in self.response_cache:
                        response_data = self.response_cache.pop(command_id)
                        return {
                            'output': response_data.get('output', ''),
                            'status': response_data.get('status', 0),
                            'error': response_data.get('error', '')
                        }
                
                # Poll for response
                self._poll_responses()
                time.sleep(0.5)  # Short sleep before checking again
            
            # Timeout
            return {
                'output': '',
                'status': 1,
                'error': f'Command timeout after {self.command_timeout}s. No response received.'
            }
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            return {
                'output': '',
                'status': 1,
                'error': f'AWS SQS error ({error_code}): {str(e)}'
            }
        except Exception as e:
            return {
                'output': '',
                'status': 1,
                'error': f'Error executing command: {str(e)}'
            }
    
    def _poll_responses(self):
        """Poll for responses from the response queue"""
        if not self.sqs_client or not self.response_queue_url:
            return
        
        try:
            response = self.sqs_client.receive_message(
                QueueUrl=self.response_queue_url,
                MaxNumberOfMessages=min(self.max_messages, 10),
                WaitTimeSeconds=1,
                VisibilityTimeout=self.visibility_timeout,
                MessageAttributeNames=['All'] if self.message_attributes else []
            )
            
            messages = response.get('Messages', [])
            
            for message in messages:
                try:
                    body = message.get('Body', '')
                    receipt_handle = message.get('ReceiptHandle')
                    
                    # Decode if base64
                    if self.use_base64:
                        try:
                            body = base64.b64decode(body).decode('utf-8')
                        except:
                            pass
                    
                    # Parse JSON
                    try:
                        data = json.loads(body)
                        command_id = data.get('command_id', 'unknown')
                        output = data.get('output', body)
                        status = data.get('status', 0)
                        error = data.get('error', '')
                    except:
                        output = body
                        status = 0
                        error = ''
                        command_id = 'unknown'
                    
                    # Store response
                    with self.response_lock:
                        self.response_cache[command_id] = {
                            'output': output,
                            'status': status,
                            'error': error,
                            'timestamp': time.time()
                        }
                    
                    # Delete message
                    if receipt_handle:
                        self.sqs_client.delete_message(
                            QueueUrl=self.response_queue_url,
                            ReceiptHandle=receipt_handle
                        )
                        
                except Exception as e:
                    print_error(f"Error processing response message: {e}")
                    continue
                    
        except ClientError as e:
            # Don't print error for every poll failure
            pass
        except Exception as e:
            # Don't print error for every poll failure
            pass
    
    def _store_response(self, command_id: str, output: str, status: int, error: str):
        """Store response from listener polling thread"""
        with self.response_lock:
            self.response_cache[command_id] = {
                'output': output,
                'status': status,
                'error': error,
                'timestamp': time.time()
            }
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return [
            'help', 'exit', 'clear', 'history',
            'cd', 'pwd', 'ls', 'whoami', 'id',
            'echo', 'env', 'export'
        ]
    
    def activate(self):
        """Activate the shell"""
        super().activate()
        if not self.sqs_client:
            self._init_from_session()
    
    def deactivate(self):
        """Deactivate the shell"""
        super().deactivate()
        # Clear response cache
        with self.response_lock:
            self.response_cache.clear()

