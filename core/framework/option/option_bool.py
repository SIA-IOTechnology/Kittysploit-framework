from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError

class OptBool(Option):
    def __init__(self, value, description, required=False, advanced=False):
        super().__init__(default=value, description=description, required=required, advanced=advanced)
    
    def _coerce_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.lower()
            if lowered in ('true', 'yes', 'y', '1', 'on'):
                return True
            if lowered in ('false', 'no', 'n', '0', 'off'):
                return False
        raise OptionValidationError(f"The value '{value}' is not a valid boolean")

    def __set__(self, instance, value):
        coerced = self._coerce_bool(value)
        super().__set__(instance, coerced)

    def validate(self):
        super().validate()
        if isinstance(self.value, bool):
            return True
        if isinstance(self.value, str):
            if self.value.lower() in ('true', 'yes', 'y', '1'):
                self.value = True
                return True
            elif self.value.lower() in ('false', 'no', 'n', '0'):
                self.value = False
                return True
        raise OptionValidationError(f"The value '{self.value}' is not a valid boolean")
