from core.framework.option.base_option import Option
from core.utils.exceptions import OptionValidationError
import re

class OptIP(Option):
    def __init__(self, value, description, required=False, advanced=False):
        super().__init__(default=value, description=description, required=required, advanced=advanced)
        
    
    def __set__(self, instance, value):
        super().__set__(instance, value)
        if isinstance(value, str):
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
                octets = value.split('.')
                for octet in octets:
                    if not 0 <= int(octet) <= 255:
                        raise OptionValidationError(f"The value '{value}' is not a valid IP address")
                self.value = value
            else:
                raise OptionValidationError(f"The value '{value}' is not a valid IP address")
        elif isinstance(value, bool):
            self.value = value
        else:
            raise OptionValidationError(f"The value '{value}' is not a valid IP address")

    def validate(self):
        super().validate()
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, str(self.value)):
            raise OptionValidationError(f"'{self.value}' n'est pas une adresse IP valide")
        
        # Vérifier que chaque octet est entre 0 et 255
        octets = str(self.value).split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                raise OptionValidationError(f"'{self.value}' n'est pas une adresse IP valide")
        
        return True