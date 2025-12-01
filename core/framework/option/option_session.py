#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Option for selecting a session from active sessions
"""

from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError
from typing import Optional, List, Dict, Any


class OptSession(Option):
    """Option for selecting a session from active sessions"""
    
    def __init__(self, default="", description="", required=False, advanced=False, session_type=None):
        """
        Initialize a session option
        
        Args:
            default: Default session ID (empty string for no default)
            description: Option description
            required: Whether the option is required
            advanced: Whether the option is advanced
            session_type: Filter by session type (e.g., 'shell', 'meterpreter', 'http', None for all)
        """
        super().__init__(default, description, required, advanced)
        self.session_type = session_type
        self._framework = None
        self._instance = None
    
    def set_framework(self, framework):
        """Set the framework instance to access session manager"""
        self._framework = framework
    
    def _get_framework(self):
        """Get framework instance from module if available"""
        if self._framework:
            return self._framework
        
        # Try to get framework from the module instance (if available)
        # This happens when the option is accessed via __get__ descriptor
        if hasattr(self, '_instance') and self._instance:
            if hasattr(self._instance, 'framework'):
                return self._instance.framework
        
        return None
    
    def _get_available_sessions(self) -> List[str]:
        """
        Get list of available session IDs
        
        Returns:
            List of session IDs
        """
        framework = self._get_framework()
        if not framework:
            return []
        
        try:
            if not hasattr(framework, 'session_manager'):
                return []
            
            session_manager = framework.session_manager
            all_sessions = session_manager.get_all_sessions()
            
            session_ids = []
            
            # Get standard sessions
            standard_sessions = all_sessions.get('standard', [])
            for session in standard_sessions:
                if self.session_type is None or getattr(session, 'session_type', None) == self.session_type:
                    session_ids.append(session.id)
            
            # Get browser sessions
            browser_sessions = all_sessions.get('browser', [])
            for session in browser_sessions:
                if self.session_type is None or session.get('type', 'browser') == self.session_type:
                    session_id = session.get('id') or session.get('session_id')
                    if session_id:
                        session_ids.append(str(session_id))
            
            return session_ids
        except Exception:
            return []
    
    def _get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific session
        
        Args:
            session_id: Session ID to look up
            
        Returns:
            Dictionary with session information or None
        """
        framework = self._get_framework()
        if not framework or not hasattr(framework, 'session_manager'):
            return None
        
        try:
            session_manager = framework.session_manager
            
            # Try standard sessions first
            session = session_manager.get_session(session_id)
            if session:
                return {
                    'id': session.id,
                    'host': session.host,
                    'port': session.port,
                    'type': session.session_type
                }
            
            # Try browser sessions
            browser_session = session_manager.get_browser_session(session_id)
            if browser_session:
                return {
                    'id': browser_session.get('id') or browser_session.get('session_id'),
                    'host': browser_session.get('ip', 'N/A'),
                    'port': browser_session.get('port', 'N/A'),
                    'type': 'browser'
                }
        except Exception:
            pass
        
        return None
    
    def validate(self):
        """
        Validate the session value
        
        Returns:
            bool: True if valid
            
        Raises:
            OptionValidationError: If validation fails
        """
        # Call parent validation first
        super().validate()
        
        # If empty and not required, it's valid
        if not self.value or self.value == "":
            if not self.required:
                return True
            raise OptionValidationError(f"The option {self.label} is required and cannot be empty")
        
        # Check if session exists
        available_sessions = self._get_available_sessions()
        
        if available_sessions and self.value not in available_sessions:
            session_info = self._get_session_info(self.value)
            if not session_info:
                valid_sessions = ', '.join(available_sessions[:5])  # Show first 5
                if len(available_sessions) > 5:
                    valid_sessions += f" ... and {len(available_sessions) - 5} more"
                raise OptionValidationError(
                    f"Invalid session '{self.value}'. Available sessions: {valid_sessions}"
                )
        
        return True
    
    def __get__(self, instance, owner):
        """Descriptor to access the value and capture module instance"""
        # Store instance reference for framework access
        if instance:
            self._instance = instance
            # Auto-set framework if available
            if hasattr(instance, 'framework') and instance.framework:
                self._framework = instance.framework
        return super().__get__(instance, owner)
    
    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the selected session
        
        Returns:
            Dictionary with session information or None
        """
        if not self.value or self.value == "":
            return None
        return self._get_session_info(self.value)
    
    def to_dict(self):
        """
        Convert the option to a dictionary with available sessions
        
        Returns:
            dict: Dictionary representing the option
        """
        base_dict = super().to_dict()
        base_dict['available_sessions'] = self._get_available_sessions()
        base_dict['session_type'] = self.session_type
        return base_dict
