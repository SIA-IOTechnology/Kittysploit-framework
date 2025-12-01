#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from typing import Dict, Any, List
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

class AWSSQSCommandShell(BaseShell):
    """AWS SQS Command Executor Shell - executes commands via AWS SQS, no interactive shell"""
    
    def __init__(self, session_id: str, session_type: str = "aws_sqs", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.listener = None
        self.command_timeout = 60
        
        # Initialize from session/listener
        self._init_from_session()
    
    def _init_from_session(self):
        """Initialize shell from session data"""
        try:
            if not self.framework or not hasattr(self.framework, 'session_manager'):
                return
            
            session = self.framework.session_manager.get_session(self.session_id)
            if not session:
                return
            
            # Try to get listener from active_listeners
            if hasattr(self.framework, 'active_listeners'):
                for listener_id, listener in self.framework.active_listeners.items():
                    # Check if listener has this session
                    if hasattr(listener, '_session_connections'):
                        if self.session_id in listener._session_connections:
                            # Check if listener has execute_command method
                            if hasattr(listener, 'execute_command'):
                                self.listener = listener
                                if hasattr(listener, 'command_timeout'):
                                    self.command_timeout = int(listener.command_timeout.value) if hasattr(listener.command_timeout, 'value') else 60
                                return
            
            # Fallback: try to get from session data
            session_data = session.data if hasattr(session, 'data') else {}
            if session_data.get('command_executor'):
                # This is a command executor session, but listener not found
                print_warning("Listener not found for command execution. Commands may not work.")
            
        except Exception as e:
            print_error(f"Error initializing AWS SQS command shell: {e}")
    
    @property
    def shell_name(self) -> str:
        return "aws_sqs_command"
    
    @property
    def prompt_template(self) -> str:
        return "aws-sqs> "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.prompt_template
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command via AWS SQS"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        if not BOTO3_AVAILABLE:
            return {'output': '', 'status': 1, 'error': 'boto3 library not installed'}
        
        if not self.listener:
            return {
                'output': '',
                'status': 1,
                'error': 'AWS SQS listener not available. Make sure the listener is running.'
            }
        
        # Add to history
        self.add_to_history(command)
        
        try:
            # Execute command via listener
            result = self.listener.execute_command(command, timeout=self.command_timeout)
            return result
            
        except Exception as e:
            return {
                'output': '',
                'status': 1,
                'error': f'Error executing command: {str(e)}'
            }
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return [
            'help', 'exit', 'clear', 'history'
        ]
    
    def activate(self):
        """Activate the shell"""
        super().activate()
        if not self.listener:
            self._init_from_session()
    
    def deactivate(self):
        """Deactivate the shell"""
        super().deactivate()

