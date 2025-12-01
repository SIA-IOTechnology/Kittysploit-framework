#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import TypeDecorator, String, Text
from sqlalchemy.ext.hybrid import hybrid_property
from typing import Any, Optional
import json

class EncryptedString(TypeDecorator):
    """Encrypted string field for SQLAlchemy"""
    
    impl = String(1000)  # Base field type
    cache_ok = True
    
    def __init__(self, length=1000, **kwargs):
        super().__init__(length, **kwargs)
        self._encryption_manager = None
    
    def set_encryption_manager(self, encryption_manager):
        """Set the encryption manager instance"""
        self._encryption_manager = encryption_manager
    
    def process_bind_param(self, value, dialect):
        """Encrypt value before storing in database"""
        if value is None:
            return None
        
        if not self._encryption_manager or not self._encryption_manager._is_initialized:
            # If encryption is not available, store as plain text (for development)
            return value
        
        try:
            return self._encryption_manager.encrypt_data(value)
        except Exception:
            # If encryption fails, store as plain text
            return value
    
    def process_result_value(self, value, dialect):
        """Decrypt value when retrieving from database"""
        if value is None:
            return None
        
        if not self._encryption_manager or not self._encryption_manager._is_initialized:
            # If encryption is not available, return as is
            return value
        
        try:
            return self._encryption_manager.decrypt_data(value)
        except Exception:
            # If decryption fails, return as is (might be plain text)
            return value

class EncryptedText(TypeDecorator):
    """Encrypted text field for SQLAlchemy"""
    
    impl = Text
    cache_ok = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._encryption_manager = None
    
    def set_encryption_manager(self, encryption_manager):
        """Set the encryption manager instance"""
        self._encryption_manager = encryption_manager
    
    def process_bind_param(self, value, dialect):
        """Encrypt value before storing in database"""
        if value is None:
            return None
        
        if not self._encryption_manager or not self._encryption_manager._is_initialized:
            # If encryption is not available, store as plain text (for development)
            return value
        
        try:
            return self._encryption_manager.encrypt_data(value)
        except Exception:
            # If encryption fails, store as plain text
            return value
    
    def process_result_value(self, value, dialect):
        """Decrypt value when retrieving from database"""
        if value is None:
            return None
        
        if not self._encryption_manager or not self._encryption_manager._is_initialized:
            # If encryption is not available, return as is
            return value
        
        try:
            return self._encryption_manager.decrypt_data(value)
        except Exception:
            # If decryption fails, return as is (might be plain text)
            return value

class EncryptedJSON(TypeDecorator):
    """Encrypted JSON field for SQLAlchemy"""
    
    impl = Text
    cache_ok = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._encryption_manager = None
    
    def set_encryption_manager(self, encryption_manager):
        """Set the encryption manager instance"""
        self._encryption_manager = encryption_manager
    
    def process_bind_param(self, value, dialect):
        """Encrypt JSON value before storing in database"""
        if value is None:
            return None
        
        if not self._encryption_manager or not self._encryption_manager._is_initialized:
            # If encryption is not available, store as JSON string
            return json.dumps(value, ensure_ascii=False)
        
        try:
            return self._encryption_manager.encrypt_data(value)
        except Exception:
            # If encryption fails, store as JSON string
            return json.dumps(value, ensure_ascii=False)
    
    def process_result_value(self, value, dialect):
        """Decrypt JSON value when retrieving from database"""
        if value is None:
            return None
        
        if not self._encryption_manager or not self._encryption_manager._is_initialized:
            # If encryption is not available, try to parse as JSON
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
        
        try:
            return self._encryption_manager.decrypt_data(value)
        except Exception:
            # If decryption fails, try to parse as JSON
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value

class EncryptedFieldMixin:
    """Mixin class to add encryption support to models"""
    
    @classmethod
    def set_encryption_manager(cls, encryption_manager):
        """Set encryption manager for all encrypted fields in this model"""
        for column in cls.__table__.columns:
            if hasattr(column.type, 'set_encryption_manager'):
                column.type.set_encryption_manager(encryption_manager)
    
    def to_dict_safe(self, exclude_encrypted=True):
        """Convert model to dictionary, optionally excluding encrypted fields"""
        result = {}
        for column in self.__table__.columns:
            if exclude_encrypted and hasattr(column.type, '_encryption_manager'):
                # For encrypted fields, show placeholder
                result[column.name] = "[ENCRYPTED]"
            else:
                result[column.name] = getattr(self, column.name)
        return result
    
    def get_encrypted_fields(self):
        """Get list of encrypted field names"""
        encrypted_fields = []
        for column in self.__table__.columns:
            if hasattr(column.type, '_encryption_manager'):
                encrypted_fields.append(column.name)
        return encrypted_fields
