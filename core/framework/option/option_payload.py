from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError
from core.utils.function import pythonize_path
import importlib

class OptPayload(Option):

    def __set__(self, instance, value):
        payload = instance._add_payload_option(value)
        if payload:
            # Store the value for this specific instance (the path, not the generated payload)
            instance_id = id(instance)
            self._instance_values[instance_id] = {
                'value': value,  # Store the path
                'display_value': str(value) if value else ""
            }
            # Also update default value for backward compatibility
            self._default_value = value
            self._default_display_value = str(value) if value else ""
        else:
            raise OptionValidationError(f"Failed to add payload option: {value}")
    
    def to_dict(self, instance=None):
        """
        Convert the option to a dictionary.
        For payloads, display_value should be the path, not the generated payload.
        We override this to avoid triggering __get__() which generates the payload.
        
        Args:
            instance: Optional instance to get values for (if None, uses default)
        
        Returns:
            dict: Dictionary representing the option
        """
        if instance is None:
            value = self._default_value
            display_value = str(self._default_value) if self._default_value else ""
        else:
            # For payloads, we want to show the path, not the generated payload
            # So we get the value directly without triggering __get__
            instance_id = id(instance)
            if instance_id in self._instance_values:
                value = self._instance_values[instance_id]['value']
                display_value = str(value) if value else ""
            else:
                value = self._default_value
                display_value = str(self._default_value) if self._default_value else ""
        
        return {
            "value": value,
            "display_value": display_value,
            "required": self.required,
            "description": self.description,
            "advanced": self.advanced
        }
    
    def __get__(self, instance, owner):
        # If accessed via class (instance is None), return the descriptor
        if instance is None:
            return self
        
        # Get the value for this specific instance
        instance_id = id(instance)
        if instance_id in self._instance_values:
            payload_path_value = self._instance_values[instance_id]['value']
        else:
            payload_path_value = self._default_value
        
        if not payload_path_value:
            return None
        
        try:
            # Load payload module
            payload_path = pythonize_path(payload_path_value)
            module_path = ".".join(("modules", payload_path))
            payload_module = getattr(importlib.import_module(module_path), "Module")()
            
            # Set framework reference if available
            if instance and hasattr(instance, 'framework') and instance.framework:
                payload_module.framework = instance.framework
            
            # Detect handler type from payload to determine which options to use
            handler_type = None
            if hasattr(payload_module, '__info__') and payload_module.__info__:
                handler_info = payload_module.__info__.get('handler')
                if handler_info:
                    # Handle enum or string
                    if hasattr(handler_info, 'value'):
                        handler_type = handler_info.value
                    elif hasattr(handler_info, 'name'):
                        handler_type = handler_info.name.lower()
                    else:
                        handler_type = str(handler_info).lower()
            
            # Copy payload options from instance to payload module if they exist
            # Adapt options based on handler type:
            # - REVERSE: uses lhost/lport (payload connects to us)
            # - BIND: uses rhost/rport (we connect to payload on target)
            if instance:
                payload_options = getattr(payload_module, 'exploit_attributes', {})
                
                # Helper function to safely get option value
                def get_option_value(opt):
                    """Safely extract value from an option descriptor or direct value"""
                    if opt is None:
                        return None
                    # If it's already a direct value (not a descriptor), return it
                    if not hasattr(opt, '__get__') and not hasattr(opt, 'value'):
                        return opt
                    # If it has a value attribute, use it
                    if hasattr(opt, 'value'):
                        return opt.value
                    # Otherwise, return the option itself (it might be a direct value)
                    return opt
                
                # Determine which options to copy based on handler type
                if handler_type == 'reverse':
                    # For reverse shells, copy lhost, lport, and obfuscator (path + options when set on exploit)
                    reverse_options = ['lhost', 'lport', 'obfuscator']
                    for option_name in reverse_options:
                        if hasattr(instance, option_name) and option_name in payload_options:
                            instance_value = getattr(instance, option_name)
                            if instance_value is not None and hasattr(payload_module, option_name):
                                payload_opt = getattr(payload_module, option_name)
                                value_to_set = get_option_value(instance_value)
                                if value_to_set is not None:
                                    if hasattr(payload_opt, '__set__'):
                                        # It's a descriptor, use __set__
                                        payload_opt.__set__(payload_module, value_to_set)
                                    elif hasattr(payload_opt, 'value'):
                                        payload_opt.value = value_to_set
                                    else:
                                        setattr(payload_module, option_name, value_to_set)
                    # Copy obfuscator options (e.g. key) from exploit to payload if both have them
                    if hasattr(instance, 'obfuscator') and get_option_value(getattr(instance, 'obfuscator', None)):
                        payload_opts_after = getattr(payload_module, 'get_options', lambda: {})()
                        for option_name in payload_opts_after:
                            if option_name not in reverse_options and hasattr(instance, option_name):
                                try:
                                    instance_value = getattr(instance, option_name)
                                    if instance_value is not None and hasattr(payload_module, option_name):
                                        payload_opt = getattr(payload_module, option_name, None)
                                        value_to_set = get_option_value(instance_value) if hasattr(instance_value, 'value') else instance_value
                                        if value_to_set is not None and payload_opt is not None:
                                            if hasattr(payload_opt, '__set__'):
                                                payload_opt.__set__(payload_module, value_to_set)
                                            elif hasattr(payload_opt, 'value'):
                                                payload_opt.value = value_to_set
                                            else:
                                                setattr(payload_module, option_name, value_to_set)
                                except Exception:
                                    pass
                elif handler_type == 'bind':
                    # For bind shells, copy rhost and rport
                    bind_options = ['rhost', 'rport']
                    for option_name in bind_options:
                        if hasattr(instance, option_name) and option_name in payload_options:
                            instance_value = getattr(instance, option_name)
                            if instance_value is not None and hasattr(payload_module, option_name):
                                payload_opt = getattr(payload_module, option_name)
                                value_to_set = get_option_value(instance_value)
                                if value_to_set is not None:
                                    if hasattr(payload_opt, '__set__'):
                                        # It's a descriptor, use __set__
                                        payload_opt.__set__(payload_module, value_to_set)
                                    elif hasattr(payload_opt, 'value'):
                                        payload_opt.value = value_to_set
                                    else:
                                        setattr(payload_module, option_name, value_to_set)
                else:
                    # Fallback: copy all matching options
                    for option_name in payload_options.keys():
                        if hasattr(instance, option_name):
                            instance_value = getattr(instance, option_name)
                            if instance_value is not None and hasattr(payload_module, option_name):
                                payload_opt = getattr(payload_module, option_name)
                                value_to_set = get_option_value(instance_value)
                                if value_to_set is not None:
                                    if hasattr(payload_opt, '__set__'):
                                        # It's a descriptor, use __set__
                                        payload_opt.__set__(payload_module, value_to_set)
                                    elif hasattr(payload_opt, 'value'):
                                        payload_opt.value = value_to_set
                                    else:
                                        setattr(payload_module, option_name, value_to_set)
            
            # Generate the raw payload
            raw_payload = payload_module.generate()
            
            if not raw_payload:
                raise OptionValidationError(f"Failed to generate payload from module: {payload_path_value}")
            
            # Check if encoder is specified in payload options
            encoder_path = None
            if hasattr(payload_module, 'encoder'):
                encoder_opt = payload_module.encoder
                if hasattr(encoder_opt, 'value') and encoder_opt.value:
                    encoder_path = encoder_opt.value
                elif isinstance(encoder_opt, str) and encoder_opt:
                    encoder_path = encoder_opt
            
            # Apply encoder if specified
            if encoder_path:
                try:
                    # Load encoder module
                    encoder_module_path = pythonize_path(encoder_path)
                    encoder_full_path = ".".join(("modules", encoder_module_path))
                    encoder_module = getattr(importlib.import_module(encoder_full_path), "Module")()
                    
                    # Set framework reference if available
                    if instance and hasattr(instance, 'framework') and instance.framework:
                        encoder_module.framework = instance.framework
                    
                    # Apply encoding
                    if hasattr(encoder_module, 'encode'):
                        encoded_payload = encoder_module.encode(raw_payload)
                        return encoded_payload
                    else:
                        raise OptionValidationError(f"Encoder module {encoder_path} does not have encode() method")
                        
                except ImportError as e:
                    raise OptionValidationError(f"Failed to import encoder module: {encoder_path} - {e}")
                except Exception as e:
                    raise OptionValidationError(f"Failed to apply encoder: {e}")
            
            # Return raw payload if no encoder
            return raw_payload
            
        except ImportError as e:
            raise OptionValidationError(f"Failed to import payload module: {payload_path_value} - {e}")
        except Exception as e:
            raise OptionValidationError(f"Error generating payload: {e}")
    
    def __delete__(self, instance):
        """Delete the value for this specific instance"""
        instance_id = id(instance)
        if instance_id in self._instance_values:
            del self._instance_values[instance_id]
        self._default_value = ""
        self._default_display_value = ""
        