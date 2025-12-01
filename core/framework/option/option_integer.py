from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError

class OptInteger(Option):
    def __init__(self, value, description, required=False, advanced=False):
        super().__init__(default=value, description=description, required=required, advanced=advanced)

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
            raise OptionValidationError(f"The value '{value}' is not a valid integer")
    
    def __int__(self):
        """Permet la conversion automatique en int"""
        if self._default_value is None:
            return 0
        return int(self._default_value)
    
    def __str__(self):
        """Permet la conversion automatique en string"""
        if self._default_value is None:
            return "0"
        return str(self._default_value)
    
    def validate(self):
        super().validate()
        try:
            int(self.value)
            return True
        except (ValueError, TypeError):
            raise OptionValidationError(f"The value '{self.value}' is not a valid integer")
