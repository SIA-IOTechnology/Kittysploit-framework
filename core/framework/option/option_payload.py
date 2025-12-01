from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError
from core.utils.function import pythonize_path
import importlib

class OptPayload(Option):

    def __set__(self, instance, value):
        payload = instance._add_payload_option(value)
        if payload:
            self.value = value
        else:
            raise OptionValidationError(f"Failed to add payload option: {value}")
    
    def __get__(self, instance, owner):
        if not self.value:
            return None
        
        try:
            # Load payload module
            payload_path = pythonize_path(self.value)
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
                
                # Determine which options to copy based on handler type
                if handler_type == 'reverse':
                    # For reverse shells, copy lhost and lport
                    reverse_options = ['lhost', 'lport']
                    for option_name in reverse_options:
                        if hasattr(instance, option_name) and option_name in payload_options:
                            instance_value = getattr(instance, option_name)
                            if hasattr(payload_module, option_name):
                                payload_opt = getattr(payload_module, option_name)
                                if hasattr(payload_opt, 'value'):
                                    payload_opt.value = instance_value.value if hasattr(instance_value, 'value') else instance_value
                                else:
                                    setattr(payload_module, option_name, instance_value)
                elif handler_type == 'bind':
                    # For bind shells, copy rhost and rport
                    bind_options = ['rhost', 'rport']
                    for option_name in bind_options:
                        if hasattr(instance, option_name) and option_name in payload_options:
                            instance_value = getattr(instance, option_name)
                            if hasattr(payload_module, option_name):
                                payload_opt = getattr(payload_module, option_name)
                                if hasattr(payload_opt, 'value'):
                                    payload_opt.value = instance_value.value if hasattr(instance_value, 'value') else instance_value
                                else:
                                    setattr(payload_module, option_name, instance_value)
                else:
                    # Fallback: copy all matching options
                    for option_name in payload_options.keys():
                        if hasattr(instance, option_name):
                            instance_value = getattr(instance, option_name)
                            if hasattr(payload_module, option_name):
                                payload_opt = getattr(payload_module, option_name)
                                if hasattr(payload_opt, 'value'):
                                    payload_opt.value = instance_value.value if hasattr(instance_value, 'value') else instance_value
                                else:
                                    setattr(payload_module, option_name, instance_value)
            
            # Generate the raw payload
            raw_payload = payload_module.generate()
            
            if not raw_payload:
                raise OptionValidationError(f"Failed to generate payload from module: {self.value}")
            
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
            raise OptionValidationError(f"Failed to import payload module: {self.value} - {e}")
        except Exception as e:
            raise OptionValidationError(f"Error generating payload: {e}")
    
    def __delete__(self, instance):
        del self.value
        