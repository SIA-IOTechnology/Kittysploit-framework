#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.utils.exceptions import OptionValidationError

class Option:
    """Class representing a module option."""
    
    def __init__(self, default, description="", required=False, advanced=False):
        """
        Initialize a new option.
        
        Args:
            default: Default value of the option
            description: Description of the option
            required: Indicates if the option is required
            advanced: Indicates if the option is advanced
        """
        self.description = description
        self.required = required
        self.advanced = advanced
        self.label = ""  # Will be defined by the metaclass
        
        # Store values per instance to avoid sharing between module instances
        self._instance_values = {}
        self._default_value = default
        
        # Initialize the default value
        if default is not None:
            self._default_display_value = str(default)
        else:
            self._default_display_value = ""
    
    def __get__(self, instance, owner):
        """Descripteur pour accéder à la valeur"""
        # Si accès via la classe (instance is None), retourner le descripteur
        if instance is None:
            return self
        
        # Si une valeur spécifique à l'instance existe, la retourner
        instance_id = id(instance)
        if instance_id in self._instance_values:
            value = self._instance_values[instance_id]['value']
            # S'assurer qu'on ne retourne pas un objet Option par erreur
            if isinstance(value, Option):
                return value._default_value
            return value
        
        # Sinon, retourner la valeur par défaut
        # S'assurer qu'on ne retourne pas un objet Option par erreur
        if isinstance(self._default_value, Option):
            return self._default_value._default_value
        return self._default_value
    
    def __set__(self, instance, value):
        """Descripteur pour définir la valeur"""
        instance_id = id(instance)
        display_value = str(value) if value is not None else ""
        
        # Stocker la valeur pour cette instance spécifique
        self._instance_values[instance_id] = {
            'value': value,
            'display_value': display_value
        }
        
        # Mettre à jour aussi la valeur par défaut pour compatibilité
        self._default_value = value
        self._default_display_value = display_value
    
    def validate(self, instance=None):
        """
        Validate the value of the option.
        
        Args:
            instance: Optional instance to validate for (if None, validates default)
        
        Returns:
            bool: True if the value is valid
            
        Raises:
            OptionValidationError: If the validation fails
        """
        if instance is None:
            value = self._default_value
        else:
            value = self.__get__(instance, None)
        
        if self.required and (value is None or value == ""):
            raise OptionValidationError(f"The option {self.label} is required and cannot be empty")
        return True
    
    def to_dict(self, instance=None):
        """
        Convert the option to a dictionary.
        
        Args:
            instance: Optional instance to get values for (if None, uses default)
        
        Returns:
            dict: Dictionary representing the option
        """
        if instance is None:
            value = self._default_value
            display_value = self._default_display_value
        else:
            value = self.__get__(instance, None)
            if id(instance) in self._instance_values:
                display_value = self._instance_values[id(instance)]['display_value']
            else:
                display_value = self._default_display_value
        
        return {
            "value": value,
            "display_value": display_value,
            "required": self.required,
            "description": self.description,
            "advanced": self.advanced
        }
    
    @property
    def value(self):
        """Legacy property for backward compatibility - returns default value"""
        return self._default_value
    
    @value.setter
    def value(self, val):
        """Legacy setter for backward compatibility"""
        self._default_value = val
        self._default_display_value = str(val)
