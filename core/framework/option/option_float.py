from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError

class OptFloat(Option):

    def __init__(self, value, description, required=False, advanced=False):
        super().__init__(default=value, description=description, required=required, advanced=advanced)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        try:
            float_value = float(value)
            display_value = str(value)
        except ValueError:
            raise OptionValidationError(f"The value '{value}' is not a valid float")    
        
        instance_id = id(instance)
        self._instance_values[instance_id] = {
            'value': float_value,
            'display_value': display_value
        }
        self._default_value = float_value
        self._default_display_value = display_value

    def __str__(self):
        if self._default_value is None:
            return "0.0"
        return str(self._default_value)

    def validate(self):
        super().validate()
        if isinstance(self.value, float):
            return True
        raise OptionValidationError(f"The value '{self.value}' is not a valid float")