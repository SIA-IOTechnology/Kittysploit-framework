from core.framework.option.option_integer import OptInteger
from core.utils.exceptions import OptionValidationError

class OptPort(OptInteger):

    def __init__(self, value, description, required=False, advanced=False):
        super().__init__(value, description, required, advanced)

    def __set__(self, instance, value):
        try:
            int_value = int(value)
            display_value = str(value)
            
            # Stocker la valeur pour cette instance spécifique
            instance_id = id(instance)
            self._instance_values[instance_id] = {
                'value': int_value,
                'display_value': display_value
            }
            
            # Mettre à jour aussi la valeur par défaut pour compatibilité
            self._default_value = int_value
            self._default_display_value = display_value
            
        except ValueError:
            raise OptionValidationError(f"The value '{value}' is not a valid port")

    def validate(self):
        super().validate()
        port = int(self.value)
        if 0 <= port <= 65535:
            return True
        raise OptionValidationError(f"The port '{port}' is not valid (must be between 0 and 65535)")
