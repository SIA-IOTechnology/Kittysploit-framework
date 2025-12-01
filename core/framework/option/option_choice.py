#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError

class OptChoice(Option):
    """Option for selecting from a list of choices"""
    
    def __init__(self, default="", description="", required=False, choices=None):
        """
        Initialize a choice option
        
        Args:
            default: Default value
            description: Option description
            required: Whether the option is required
            choices: List of valid choices
        """
        self.choices = choices or []
        self.advanced = False
        
        # Validate default value if provided
        if default and self.choices and default not in self.choices:
            raise OptionValidationError(f"Invalid default choice '{default}'. Valid choices: {', '.join(self.choices)}")
        
        super().__init__(default, description, required)
    
    def __set__(self, instance, value):
        """Set the value with validation"""
        # Validate the value before storing it (only if choices are defined)
        if self.choices and value not in self.choices:
            raise OptionValidationError(f"Invalid choice '{value}'. Valid choices: {', '.join(self.choices)}")
        
        # Store the value for this specific instance
        instance_id = id(instance)
        display_value = str(value) if value is not None else ""
        
        self._instance_values[instance_id] = {
            'value': value,
            'display_value': display_value
        }
        
        # Update the default value for compatibility
        self._default_value = value
        self._default_display_value = display_value
    
    def validate(self, value):
        """Validate the choice value"""
        if self.choices and value not in self.choices:
            raise OptionValidationError(f"Invalid choice '{value}'. Valid choices: {', '.join(self.choices)}")
        return value
    
    def display_value(self):
        """Return the display value"""
        return str(self.value)
