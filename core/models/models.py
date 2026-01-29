#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Table, Index, CheckConstraint, UniqueConstraint, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, validates
from datetime import datetime
import re
from core.utils.validate import validate_hash_type
from core.models.encrypted_fields import EncryptedString, EncryptedText, EncryptedFieldMixin

Base = declarative_base()

class Workspace(Base):
    """Workspace model - represents a logical workspace in the database"""
    __tablename__ = 'workspaces'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    hosts = relationship("Host", back_populates="workspace", cascade="all, delete-orphan")
    tasks = relationship("Task", back_populates="workspace", cascade="all, delete-orphan")
    notes = relationship("Note", back_populates="workspace", cascade="all, delete-orphan")
    loot = relationship("Loot", back_populates="workspace", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Workspace(name='{self.name}', active={self.is_active})>"

# Association tables for many-to-many relationships
host_services = Table('host_services', Base.metadata,
    Column('host_id', Integer, ForeignKey('hosts.id')),
    Column('service_id', Integer, ForeignKey('services.id'))
)

host_vulnerabilities = Table('host_vulnerabilities', Base.metadata,
    Column('host_id', Integer, ForeignKey('hosts.id')),
    Column('vulnerability_id', Integer, ForeignKey('vulnerabilities.id'))
)

class Host(Base):
    """Represents a host in the workspace"""
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False)
    address = Column(String(255), nullable=False, index=True)
    hostname = Column(String(255), index=True)
    os = Column(String(255))
    os_version = Column(String(255))
    mac = Column(String(17))  # MAC address format: XX:XX:XX:XX:XX:XX
    status = Column(String(50), default='unknown')  # up, down, unknown
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Constraints
    __table_args__ = (
        CheckConstraint('status IN ("up", "down", "unknown")', name='check_host_status'),
        CheckConstraint('LENGTH(address) > 0', name='check_address_not_empty'),
        Index('idx_host_address_status', 'address', 'status'),
    )
    
    @validates('address')
    def validate_address(self, key, address):
        """Validate IP address or hostname format"""
        if not address or len(address.strip()) == 0:
            raise ValueError("Address cannot be empty")
        return address.strip()
    
    @validates('mac')
    def validate_mac(self, key, mac):
        """Validate MAC address format"""
        if mac and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
            raise ValueError("Invalid MAC address format")
        return mac
    
    def __repr__(self):
        return f"<Host {self.address} ({self.hostname or 'unknown'})>"
    
    def to_dict(self):
        """Convert host to dictionary"""
        return {
            'id': self.id,
            'address': self.address,
            'hostname': self.hostname,
            'os': self.os,
            'os_version': self.os_version,
            'mac': self.mac,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_services_count(self):
        """Get the number of services for this host"""
        return len(self.services) if self.services else 0
    
    def get_vulnerabilities_count(self):
        """Get the number of vulnerabilities for this host"""
        return len(self.vulnerabilities) if self.vulnerabilities else 0
    
    # Relationships
    workspace = relationship("Workspace", back_populates="hosts")
    services = relationship("Service", secondary=host_services, back_populates="hosts")
    vulnerabilities = relationship("Vulnerability", secondary=host_vulnerabilities, back_populates="hosts")
    credentials = relationship("Credential", back_populates="host")
    notes = relationship("Note", back_populates="host")

class Service(Base):
    """Represents a network service"""
    __tablename__ = 'services'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(50), nullable=False)  # tcp, udp
    state = Column(String(50), default='unknown')  # open, closed, filtered, unknown
    version = Column(String(255))
    banner = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Constraints
    __table_args__ = (
        CheckConstraint('port >= 1 AND port <= 65535', name='check_port_range'),
        CheckConstraint('protocol IN ("tcp", "udp")', name='check_protocol'),
        CheckConstraint('state IN ("open", "closed", "filtered", "unknown")', name='check_service_state'),
        UniqueConstraint('port', 'protocol', name='unique_port_protocol'),
        Index('idx_service_port_protocol', 'port', 'protocol'),
    )
    
    @validates('port')
    def validate_port(self, key, port):
        """Validate port number"""
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return port
    
    def __repr__(self):
        return f"<Service {self.name}:{self.port}/{self.protocol} ({self.state})>"
    
    def to_dict(self):
        """Convert service to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state,
            'version': self.version,
            'banner': self.banner,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_service_string(self):
        """Get service string in format: name:port/protocol"""
        return f"{self.name or 'unknown'}:{self.port}/{self.protocol}"
    
    # Relationships
    hosts = relationship("Host", secondary=host_services, back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service")

class Vulnerability(Base):
    """Represents a vulnerability"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    cve = Column(String(50), index=True)
    cvss_score = Column(String(10))
    risk_level = Column(String(50), default='unknown')  # critical, high, medium, low, unknown
    proof_of_concept = Column(Text)
    remediation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    service_id = Column(Integer, ForeignKey('services.id'))
    
    # Constraints
    __table_args__ = (
        CheckConstraint('risk_level IN ("critical", "high", "medium", "low", "unknown")', name='check_risk_level'),
        CheckConstraint('LENGTH(name) > 0', name='check_vuln_name_not_empty'),
        Index('idx_vuln_cve_risk', 'cve', 'risk_level'),
    )
    
    @validates('cve')
    def validate_cve(self, key, cve):
        """Validate CVE format"""
        if cve and not re.match(r'^CVE-\d{4}-\d{4,}$', cve):
            raise ValueError("Invalid CVE format (expected: CVE-YYYY-NNNN)")
        return cve
    
    @validates('cvss_score')
    def validate_cvss_score(self, key, score):
        """Validate CVSS score format"""
        if score and not re.match(r'^\d+\.\d+$', score):
            raise ValueError("Invalid CVSS score format (expected: X.X)")
        return score
    
    def __repr__(self):
        return f"<Vulnerability {self.name} ({self.risk_level})>"
    
    def to_dict(self):
        """Convert vulnerability to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'cve': self.cve,
            'cvss_score': self.cvss_score,
            'risk_level': self.risk_level,
            'proof_of_concept': self.proof_of_concept,
            'remediation': self.remediation,
            'service_id': self.service_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_risk_score(self):
        """Get numeric risk score based on risk level"""
        risk_scores = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'unknown': 1
        }
        return risk_scores.get(self.risk_level, 1)
    
    # Relationships
    hosts = relationship("Host", secondary=host_vulnerabilities, back_populates="vulnerabilities")
    service = relationship("Service", back_populates="vulnerabilities")

class Credential(Base, EncryptedFieldMixin):
    """Represents credentials found during testing"""
    __tablename__ = 'credentials'
    
    id = Column(Integer, primary_key=True)
    username = Column(EncryptedString(255), index=True)  # Encrypted username
    password = Column(EncryptedString(255))  # Encrypted password
    password_hash = Column(EncryptedString(255))  # Encrypted password hash
    hash_type = Column(String(50))  # md5, sha1, sha256, bcrypt, etc. (not encrypted)
    source = Column(String(255))  # Where the credential was found (not encrypted)
    is_valid = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    
    # Constraints
    __table_args__ = (
        CheckConstraint('username IS NOT NULL OR password IS NOT NULL OR password_hash IS NOT NULL', 
                       name='check_credential_has_data'),
        Index('idx_cred_username_host', 'username', 'host_id'),
    )
    
    @validates('hash_type')
    def validate_hash_type(self, key, hash_type):
        """Validate hash type"""
        if hash_type and not validate_hash_type(hash_type.lower()):
            raise ValueError("Invalid hash type. Must be one of: md5, sha1, sha256, bcrypt")
        return hash_type.lower() if hash_type else None
    
    def __repr__(self):
        return f"<Credential {self.username or 'hash'}@{self.host_id}>"
    
    def to_dict(self):
        """Convert credential to dictionary (excluding sensitive data)"""
        return {
            'id': self.id,
            'username': self.username,
            'has_password': bool(self.password),
            'has_hash': bool(self.password_hash),
            'hash_type': self.hash_type,
            'source': self.source,
            'is_valid': self.is_valid,
            'host_id': self.host_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_credential_type(self):
        """Get the type of credential (password, hash, or both)"""
        if self.password and self.password_hash:
            return 'both'
        elif self.password:
            return 'password'
        elif self.password_hash:
            return 'hash'
        else:
            return 'none'
    
    # Relationships
    host = relationship("Host", back_populates="credentials")

class Note(Base):
    """Represents notes and findings"""
    __tablename__ = 'notes'
    
    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False)
    title = Column(String(255), nullable=False, index=True)
    content = Column(Text)
    category = Column(String(50), default='general')  # recon, exploit, post, general, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    
    # Constraints
    __table_args__ = (
        CheckConstraint('LENGTH(title) > 0', name='check_note_title_not_empty'),
        CheckConstraint('category IN ("recon", "exploit", "post", "general", "other")', name='check_note_category'),
        Index('idx_note_category_host', 'category', 'host_id'),
    )
    
    def __repr__(self):
        return f"<Note {self.title} ({self.category})>"
    
    def to_dict(self):
        """Convert note to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'category': self.category,
            'host_id': self.host_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_content_preview(self, max_length=100):
        """Get a preview of the content"""
        if not self.content:
            return ""
        return self.content[:max_length] + "..." if len(self.content) > max_length else self.content
    
    # Relationships
    workspace = relationship("Workspace", back_populates="notes")
    host = relationship("Host", back_populates="notes")

class Loot(Base, EncryptedFieldMixin):
    """Represents data exfiltrated during testing"""
    __tablename__ = 'loots'
    
    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False)
    name = Column(String(255), nullable=False, index=True)  # Not encrypted (for searching)
    loot_type = Column(String(50), default='file')  # password file, shell history, database, etc. (not encrypted)
    content = Column(EncryptedText)  # Encrypted content
    file_path = Column(String(500))  # Path to the loot file in workspace (not encrypted)
    file_size = Column(Integer)  # Size in bytes (not encrypted)
    created_at = Column(DateTime, default=datetime.utcnow)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    
    # Constraints
    __table_args__ = (
        CheckConstraint('LENGTH(name) > 0', name='check_loot_name_not_empty'),
        CheckConstraint('file_size >= 0', name='check_file_size_positive'),
        Index('idx_loot_type_host', 'loot_type', 'host_id'),
    )
    
    def __repr__(self):
        return f"<Loot {self.name} ({self.loot_type})>"
    
    def to_dict(self):
        """Convert loot to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'loot_type': self.loot_type,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'host_id': self.host_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def get_file_size_human(self):
        """Get human-readable file size"""
        if not self.file_size:
            return "Unknown"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024.0
        return f"{self.file_size:.1f} TB"
    
    # Relationships
    workspace = relationship("Workspace", back_populates="loot")
    host = relationship("Host")

class Task(Base):
    """Represents tasks and todos"""
    __tablename__ = 'tasks'
    
    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    status = Column(String(50), default='pending')  # pending, in progress, completed, cancelled
    priority = Column(String(50), default='medium')  # high, medium, low
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    
    # Constraints
    __table_args__ = (
        CheckConstraint('LENGTH(title) > 0', name='check_task_title_not_empty'),
        CheckConstraint('status IN ("pending", "in progress", "completed", "cancelled")', name='check_task_status'),
        CheckConstraint('priority IN ("high", "medium", "low")', name='check_task_priority'),
        Index('idx_task_status_priority', 'status', 'priority'),
    )
    
    def __repr__(self):
        return f"<Task {self.title} ({self.status})>"
    
    def to_dict(self):
        """Convert task to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'priority': self.priority,
            'host_id': self.host_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
    
    def is_completed(self):
        """Check if task is completed"""
        return self.status == 'completed'
    
    def mark_completed(self):
        """Mark task as completed"""
        self.status = 'completed'
        self.completed_at = datetime.utcnow()
    
    # Relationships
    workspace = relationship("Workspace", back_populates="tasks")
    host = relationship("Host")

class Module(Base):
    """Represents a module in the framework"""
    __tablename__ = 'modules'
    
    id = Column(Integer, primary_key=True)
    # Module names are not guaranteed unique across the filesystem; use `path` as the unique key.
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    type = Column(String(50), nullable=False)  # exploits, auxiliary, scanner, post, etc.
    path = Column(String(500), nullable=False, unique=True, index=True)  # Unique module path (stable identifier)
    author = Column(String(255))
    version = Column(String(50))
    cve = Column(String(50), index=True)  # For exploits
    references = Column(Text)  # JSON array of references
    tags = Column(Text)  # JSON array of tags
    options = Column(Text)  # JSON object of module options
    file_hash = Column(String(64))  # SHA256 hash of the module file
    file_mtime = Column(DateTime)  # Last modification time of the file
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Constraints
    __table_args__ = (
        CheckConstraint('LENGTH(name) > 0', name='check_module_name_not_empty'),
        CheckConstraint("type IN ('exploits', 'auxiliary', 'scanner', 'post', 'payloads', 'workflow', 'listeners', 'browser_exploits', 'browser_auxiliary', 'docker_environment', 'encoders', 'obfuscator', 'backdoors', 'shortcut')", name='check_module_type'),
        CheckConstraint('LENGTH(path) > 0', name='check_module_path_not_empty'),
        Index('idx_module_type_active', 'type', 'is_active'),
    )
    
    @validates('cve')
    def validate_cve(self, key, cve):
        """Validate CVE format"""
        if cve and not re.match(r'^CVE-\d{4}-\d{4,}$', cve):
            raise ValueError("Invalid CVE format (expected: CVE-YYYY-NNNN)")
        return cve
    
    def __repr__(self):
        return f"<Module {self.name} ({self.type})>"
    
    def to_dict(self):
        """Convert module to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'type': self.type,
            'path': self.path,
            'author': self.author,
            'version': self.version,
            'cve': self.cve,
            'references': self.references,
            'tags': self.tags,
            'options': self.options,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_module_info(self):
        """Get formatted module information"""
        info = f"Module: {self.name}\n"
        info += f"Type: {self.type}\n"
        if self.description:
            info += f"Description: {self.description}\n"
        if self.author:
            info += f"Author: {self.author}\n"
        if self.version:
            info += f"Version: {self.version}\n"
        if self.cve:
            info += f"CVE: {self.cve}\n"
        return info 

class CommandHistory(Base, EncryptedFieldMixin):
    """Command history model for storing encrypted command history"""
    __tablename__ = 'command_history'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    command = Column(EncryptedString(1000), nullable=False)  # Encrypted command string
    success = Column(Boolean, default=True)
    args = Column(EncryptedText)  # Encrypted arguments as JSON
    user_id = Column(String(100))  # Optional user identifier
    session_id = Column(String(100))  # Optional session identifier
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=True)
    
    # Relationships
    workspace = relationship("Workspace", backref="command_history")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_command_history_timestamp', 'timestamp'),
        Index('idx_command_history_user_id', 'user_id'),
        Index('idx_command_history_workspace_id', 'workspace_id'),
    )
    
    def __repr__(self):
        return f"<CommandHistory(id={self.id}, command='{self.command[:50]}...', timestamp={self.timestamp})>"

class Session(Base, EncryptedFieldMixin):
    """Session model for storing encrypted session data"""
    __tablename__ = 'sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(100), unique=True, nullable=False)  # Unique session identifier
    session_type = Column(String(50), nullable=False)  # shell, meterpreter, http, etc.
    target_host = Column(EncryptedString(255))  # Encrypted target host
    target_port = Column(Integer)  # Target port
    local_host = Column(EncryptedString(255))  # Encrypted local host
    local_port = Column(Integer)  # Local port
    payload = Column(EncryptedString(500))  # Encrypted payload information
    handler = Column(EncryptedString(500))  # Encrypted handler information
    
    # Session metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    is_interactive = Column(Boolean, default=False)
    
    # Session data
    session_data = Column(EncryptedText)  # Encrypted session-specific data (JSON)
    session_info = Column(EncryptedText)  # Encrypted additional session information
    
    # Workspace relationship
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=True)
    workspace = relationship("Workspace", backref="sessions")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_sessions_session_id', 'session_id'),
        Index('idx_sessions_session_type', 'session_type'),
        Index('idx_sessions_is_active', 'is_active'),
        Index('idx_sessions_workspace_id', 'workspace_id'),
        Index('idx_sessions_created_at', 'created_at'),
        Index('idx_sessions_last_seen', 'last_seen'),
    )
    
    def __repr__(self):
        return f"<Session(id={self.id}, session_id='{self.session_id}', type='{self.session_type}', active={self.is_active})>"
    
    def to_dict(self):
        """Convert session to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'session_type': self.session_type,
            'target_host': self.target_host,
            'target_port': self.target_port,
            'local_host': self.local_host,
            'local_port': self.local_port,
            'payload': self.payload,
            'handler': self.handler,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_active': self.is_active,
            'is_interactive': self.is_interactive,
            'session_data': self.session_data,
            'session_info': self.session_info,
            'workspace_id': self.workspace_id
        }

class ProxyFlow(Base, EncryptedFieldMixin):
    """Proxy flow model - stores HTTP flows captured by kittyproxy"""
    __tablename__ = 'proxy_flows'
    
    id = Column(Integer, primary_key=True)
    flow_id = Column(String(100), unique=True, nullable=False)  # Unique flow identifier from mitmproxy (not encrypted for indexing)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False)
    workspace = relationship("Workspace", backref="proxy_flows")
    
    # Request data
    method = Column(String(10), nullable=False)  # Not encrypted (metadata)
    scheme = Column(String(10))  # Not encrypted (metadata)
    host = Column(EncryptedString(255))  # Encrypted (sensitive)
    path = Column(EncryptedText)  # Encrypted (sensitive)
    url = Column(EncryptedText)  # Encrypted (sensitive - contains full URL)
    request_headers = Column(EncryptedText)  # Encrypted (JSON encoded - contains sensitive headers)
    request_content = Column(EncryptedText)  # Encrypted (Base64 encoded - contains request body)
    request_content_length = Column(Integer, default=0)  # Not encrypted (metadata)
    
    # Response data
    status_code = Column(Integer)  # Not encrypted (metadata)
    response_headers = Column(EncryptedText)  # Encrypted (JSON encoded - contains sensitive headers)
    response_content = Column(EncryptedText)  # Encrypted (Base64 encoded - contains response body)
    response_content_length = Column(Integer, default=0)  # Not encrypted (metadata)
    response_reason = Column(EncryptedString(100))  # Encrypted (may contain sensitive info)
    
    # Metadata
    timestamp_start = Column(Float, nullable=False)  # Not encrypted (metadata)
    duration = Column(Float)  # Not encrypted (metadata)
    duration_ms = Column(Integer)  # Not encrypted (metadata)
    response_size = Column(Integer)  # Not encrypted (metadata)
    intercepted = Column(Boolean, default=False)  # Not encrypted (metadata)
    source = Column(String(50))  # Not encrypted (metadata - e.g., 'api_tester')
    
    # Analysis data (stored as JSON) - encrypted as may contain sensitive info
    technologies = Column(EncryptedText)  # Encrypted (JSON encoded)
    fingerprint = Column(EncryptedText)  # Encrypted (JSON encoded)
    module_suggestions = Column(EncryptedText)  # Encrypted (JSON encoded)
    endpoints = Column(EncryptedText)  # Encrypted (JSON encoded)
    discovered_endpoints = Column(EncryptedText)  # Encrypted (JSON encoded list)
    
    # WebSocket data
    is_websocket = Column(Boolean, default=False)  # Not encrypted (metadata)
    ws_messages = Column(EncryptedText)  # Encrypted (JSON encoded - contains WebSocket messages)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes for performance (only on non-encrypted fields)
    __table_args__ = (
        Index('idx_proxy_flows_flow_id', 'flow_id'),
        Index('idx_proxy_flows_workspace_id', 'workspace_id'),
        Index('idx_proxy_flows_timestamp', 'timestamp_start'),
        Index('idx_proxy_flows_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f"<ProxyFlow(id={self.id}, flow_id='{self.flow_id}', url='{self.url[:50]}...', workspace_id={self.workspace_id})>"
    
    def to_dict(self):
        """Convert flow to dictionary for JSON serialization"""
        import json
        return {
            'id': self.flow_id,
            'method': self.method,
            'scheme': self.scheme,
            'host': self.host,
            'path': self.path,
            'url': self.url,
            'timestamp_start': self.timestamp_start,
            'status_code': self.status_code,
            'duration': self.duration,
            'duration_ms': self.duration_ms,
            'intercepted': self.intercepted,
            'source': self.source,
            'response_size': self.response_size,
            'is_websocket': self.is_websocket,
            'request': {
                'headers': json.loads(self.request_headers) if self.request_headers else {},
                'content_bs64': self.request_content or '',
                'content_length': self.request_content_length
            },
            'response': {
                'headers': json.loads(self.response_headers) if self.response_headers else {},
                'content_bs64': self.response_content or '',
                'content_length': self.response_content_length,
                'reason': self.response_reason or ''
            } if self.status_code else None,
            'technologies': json.loads(self.technologies) if self.technologies else {},
            'fingerprint': json.loads(self.fingerprint) if self.fingerprint else {},
            'module_suggestions': json.loads(self.module_suggestions) if self.module_suggestions else [],
            'endpoints': json.loads(self.endpoints) if self.endpoints else {},
            'discovered_endpoints': json.loads(self.discovered_endpoints) if self.discovered_endpoints else [],
            'ws_messages': json.loads(self.ws_messages) if self.ws_messages else [],
            'messages': json.loads(self.ws_messages) if self.ws_messages else [],
        }

class ProxyEndpoint(Base, EncryptedFieldMixin):
    """Proxy endpoint model - stores discovered endpoints from flows"""
    __tablename__ = 'proxy_endpoints'
    
    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False)
    workspace = relationship("Workspace", backref="proxy_endpoints")
    
    # Endpoint data
    url = Column(EncryptedText, nullable=False)  # Encrypted (sensitive - contains full URL)
    endpoint_type = Column(String(50))  # Not encrypted (metadata - 'api_endpoint', 'html_link', etc.)
    category = Column(String(50))  # Not encrypted (metadata - 'html_links', 'api_endpoints', etc.)
    
    # Source information
    source_flow_id = Column(String(100))  # Not encrypted (metadata - Flow ID that discovered this endpoint)
    source_url = Column(EncryptedText)  # Encrypted (sensitive - URL of the flow that discovered this endpoint)
    
    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Indexes for performance (only on non-encrypted fields)
    # Note: Cannot index encrypted fields, so we remove the unique constraint on url
    __table_args__ = (
        Index('idx_proxy_endpoints_workspace_id', 'workspace_id'),
        Index('idx_proxy_endpoints_type', 'endpoint_type'),
        Index('idx_proxy_endpoints_category', 'category'),
        Index('idx_proxy_endpoints_discovered_at', 'discovered_at'),
        # UniqueConstraint removed as url is encrypted and cannot be indexed
    )
    
    def __repr__(self):
        return f"<ProxyEndpoint(id={self.id}, url='{self.url[:50]}...', type='{self.endpoint_type}', workspace_id={self.workspace_id})>"

class Workflow(Base):
    """Represents a workflow in the framework"""
    __tablename__ = 'workflows'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    trigger = Column(String(100), default='manual')  # manual, platform:windows, platform:linux, etc.
    enabled = Column(Boolean, default=True)
    is_template = Column(Boolean, default=False, index=True)
    nodes = Column(Text)  # JSON array of workflow nodes
    edges = Column(Text)  # JSON array of workflow edges
    steps = Column(Text)  # JSON array of workflow steps
    variables = Column(Text)  # JSON object of workflow variables
    executions = Column(Integer, default=0)  # Count of executions
    last_executed = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Constraints
    __table_args__ = (
        CheckConstraint('LENGTH(name) > 0', name='check_workflow_name_not_empty'),
        Index('idx_workflow_name', 'name'),
        Index('idx_workflow_enabled', 'enabled'),
    )
    
    # Relationships
    executions_rel = relationship("WorkflowExecution", back_populates="workflow", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Workflow {self.name} ({'template' if self.is_template else 'workflow'})>"
    
    def to_dict(self):
        """Convert workflow to dictionary"""
        import json
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'trigger': self.trigger,
            'enabled': self.enabled,
            'is_template': self.is_template,
            'nodes': json.loads(self.nodes) if self.nodes else [],
            'edges': json.loads(self.edges) if self.edges else [],
            'steps': json.loads(self.steps) if self.steps else [],
            'variables': json.loads(self.variables) if self.variables else {},
            'executions': self.executions,
            'last_executed': self.last_executed.isoformat() if self.last_executed else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class WorkflowExecution(Base):
    """Represents a workflow execution record"""
    __tablename__ = 'workflow_executions'
    
    id = Column(Integer, primary_key=True)
    workflow_id = Column(Integer, ForeignKey('workflows.id'), nullable=False, index=True)
    status = Column(String(50), default='running')  # running, completed, failed, cancelled
    target_session = Column(String(100))  # Target session ID if applicable
    context = Column(Text)  # JSON object of execution context
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = Column(DateTime)
    duration = Column(Integer)  # Duration in seconds
    results = Column(Text)  # JSON object of execution results
    logs = Column(Text)  # Execution logs
    error_message = Column(Text)  # Error message if execution failed
    
    # Constraints
    __table_args__ = (
        CheckConstraint('status IN ("running", "completed", "failed", "cancelled")', name='check_execution_status'),
        Index('idx_execution_workflow_status', 'workflow_id', 'status'),
        Index('idx_execution_started_at', 'started_at'),
    )
    
    # Relationships
    workflow = relationship("Workflow", back_populates="executions_rel")
    
    def __repr__(self):
        return f"<WorkflowExecution(id={self.id}, workflow_id={self.workflow_id}, status='{self.status}')>"
    
    def to_dict(self):
        """Convert execution to dictionary"""
        import json
        return {
            'id': self.id,
            'workflow_id': self.workflow_id,
            'status': self.status,
            'target_session': self.target_session,
            'context': json.loads(self.context) if self.context else {},
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration,
            'results': json.loads(self.results) if self.results else {},
            'logs': self.logs,
            'error_message': self.error_message
        }