from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError

class OptBool(Option):
    def __init__(self, value, description, required=False, advanced=False):
        super().__init__(default=value, description=description, required=required, advanced=advanced)
    
    def __set__(self, instance, value):
        super().__set__(instance, value)
        if isinstance(value, str):
            if value.lower() in ('true', 'yes', 'y', '1'):
                self.value = True
            elif value.lower() in ('false', 'no', 'n', '0'):
                self.value = False
        elif isinstance(value, bool):
            self.value = value
        else:
            raise OptionValidationError(f"The value '{value}' is not a valid boolean")

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
