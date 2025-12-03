#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import Enum

class Handler(Enum):
    """Handler types for listeners"""
    BIND = "bind"
    REVERSE = "reverse"

class SessionType(Enum):
    """Session types"""
    SHELL = "shell"
    METERPRETER = "meterpreter"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    DISCORD = "discord"
    WEBSOCKET = "websocket"
    PHP = "php"
    PYTHON = "python"
    MYSQL = "mysql"
    FTP = "ftp"
    AWS = "aws"
    CANBUS = "canbus"
    BROWSER = "browser"

class ServiceType(Enum):
    """Service types"""
    TCP = "tcp"
    UDP = "udp"

class ServiceState(Enum):
    """Service states"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"

class RiskLevel(Enum):
    """Risk levels"""   
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

class Protocol(Enum):
    """Protocols"""
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SSH = "ssh"
    SMB = "smb"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"

class Platform(Enum):
    """Platform types"""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNIX = "unix"
    ANDROID = "android"
    IOS = "ios"
    JAVASCRIPT = "javascript"
    OTHER = "other"
    ALL = "all"

class Browser(Enum):
    """Browser types"""
    CHROME = "chrome"
    FIREFOX = "firefox"
    EDGE = "edge"
    SAFARI = "safari"
    OPERA = "opera"
    OTHER = "other"
    ALL = "all"

class PayloadCategory(Enum):
    """Payload categories"""
    STAGER = "stager"
    STAGE = "stage"
    SINGLE = "single"
    ENCODER = "encoder"
    CMD = "cmd"
    NOP = "nop"

class Arch(Enum):
    """Architecture types"""
    PYTHON = {"name": "Python", "value": "python"}
    PHP = {"name": "PHP", "value": "php"}
    PERL = {"name": "Perl", "value": "perl"}
    X86 = {"name": "x86", "value": "x86"}
    X64 = {"name": "x64", "value": "x64"}
    ARM = {"name": "ARM", "value": "arm"}
    ARM64 = {"name": "ARM64", "value": "arm64"}
    MIPS = {"name": "MIPS", "value": "mips"}
    MIPS64 = {"name": "MIPS64", "value": "mips64"}
    POWERPC = {"name": "PowerPC", "value": "powerpc"}
    SPARC = {"name": "SPARC", "value": "sparc"}
    RISC_V = {"name": "RISC-V", "value": "risc-v"}
    OTHER = {"name": "Other", "value": "other"}