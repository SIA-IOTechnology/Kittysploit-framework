from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError
import os

class OptFile(Option):
    """ Option file attribute """
    
    def __get__(self, instance, owner):
        # If accessed via class (instance is None), return the descriptor
        if instance is None:
            return self
        
        # Get the path from display_value
        instance_id = id(instance)
        if instance_id in self._instance_values:
            path = self._instance_values[instance_id].get('display_value', '')
        else:
            path = self._default_display_value
        
        if not path:
            return None
        
        if path.startswith("file://"):
            path = path.replace("file://", "")
            path = os.path.join(os.getcwd(), "data", *path.split('/'))
            
            if not os.path.exists(path):
                raise OptionValidationError("File '{}' does not exist.".format(path))
        try:
            with open(path, "r") as f:
                content = f.readlines()
                return content
        except Exception as e:
            raise OptionValidationError(f"Error reading file '{path}': {str(e)}")

    def __set__(self, instance, value):
        # Store the value using parent class method
        super().__set__(instance, value)
        
        # If value starts with file://, validate the file exists
        if value and str(value).startswith("file://"):
            path = str(value).replace("file://", "")
            path = os.path.join(os.getcwd(), "data", *path.split('/'))
            if not os.path.exists(path):
                raise OptionValidationError(f"File '{path}' does not exist.")
    
    def validate(self, instance=None):
        """
        Validate the option without reading the file.
        Only checks if a path is set, not if the file exists.
        """
        if instance is None:
            value = self._default_display_value
        else:
            instance_id = id(instance)
            if instance_id in self._instance_values:
                value = self._instance_values[instance_id].get('display_value', '')
            else:
                value = self._default_display_value
        
        if self.required and (value is None or value == ""):
            raise OptionValidationError(f"The option {self.label} is required and cannot be empty")
        return True	