from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError

class OptString(Option):
    def __init__(self, value, description, required=False, advanced=False):
        super().__init__(default=value, description=description, required=required, advanced=advanced)

    def __str__(self):
        """Permet la conversion automatique en string"""
        if self._default_value is None:
            return ""
        return str(self._default_value)
    
    def _set_value(self, instance, value):
        try:
            self.value = self.display_value = str(value)
        except Exception as e:
            raise OptionValidationError(f"Failed to set value: {e}")
