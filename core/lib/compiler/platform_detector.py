#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Platform detection for target systems
"""

import re
from typing import Dict, Optional, Tuple


class PlatformDetector:
    """Detect platform and architecture from session information"""
    
    @staticmethod
    def detect_from_session(session) -> Tuple[str, str]:
        """
        Detect platform and architecture from session
        
        Args:
            session: Session object or dict
            
        Returns:
            Tuple of (platform, architecture)
        """
        platform = 'linux'  # default
        arch = 'x64'  # default
        
        # Try to get from session attributes
        if hasattr(session, 'platform'):
            platform = session.platform.lower()
        elif isinstance(session, dict) and 'platform' in session:
            platform = session['platform'].lower()
        
        if hasattr(session, 'arch'):
            arch = session.arch.lower()
        elif isinstance(session, dict) and 'arch' in session:
            arch = session['arch'].lower()
        
        # Try to detect from uname if available
        if hasattr(session, 'cmd_exec'):
            try:
                uname_output = session.cmd_exec('uname -a')
                if uname_output:
                    platform, arch = PlatformDetector._parse_uname(uname_output)
            except Exception:
                pass
        
        return platform, arch
    
    @staticmethod
    def _parse_uname(uname_output: str) -> Tuple[str, str]:
        """Parse uname -a output"""
        platform = 'linux'
        arch = 'x64'
        
        uname_lower = uname_output.lower()
        
        # Detect platform
        if 'linux' in uname_lower:
            platform = 'linux'
        elif 'darwin' in uname_lower or 'macos' in uname_lower:
            platform = 'macos'
        elif 'windows' in uname_lower or 'microsoft' in uname_lower:
            platform = 'windows'
        elif 'freebsd' in uname_lower:
            platform = 'freebsd'
        elif 'openbsd' in uname_lower:
            platform = 'openbsd'
        elif 'netbsd' in uname_lower:
            platform = 'netbsd'
        elif 'android' in uname_lower:
            platform = 'android'
        
        # Detect architecture
        if 'x86_64' in uname_lower or 'amd64' in uname_lower:
            arch = 'x64'
        elif 'i386' in uname_lower or 'i686' in uname_lower:
            arch = 'x86'
        elif 'aarch64' in uname_lower or 'arm64' in uname_lower:
            arch = 'arm64'
        elif 'arm' in uname_lower and 'arm64' not in uname_lower:
            arch = 'arm'
        elif 'mips' in uname_lower:
            if '64' in uname_lower:
                arch = 'mips64'
            else:
                arch = 'mips'
        elif 'powerpc' in uname_lower or 'ppc' in uname_lower:
            if '64' in uname_lower:
                arch = 'ppc64'
            else:
                arch = 'ppc'
        elif 'riscv64' in uname_lower:
            arch = 'riscv64'
        
        return platform, arch
    
    @staticmethod
    def detect_from_command(session, command: str = 'uname -a') -> Tuple[str, str]:
        """
        Detect platform by executing a command on the session
        
        Args:
            session: Session with cmd_exec method
            command: Command to execute (default: uname -a)
            
        Returns:
            Tuple of (platform, architecture)
        """
        if not hasattr(session, 'cmd_exec'):
            return 'linux', 'x64'
        
        try:
            output = session.cmd_exec(command)
            if output:
                return PlatformDetector._parse_uname(output)
        except Exception:
            pass
        
        return 'linux', 'x64'

