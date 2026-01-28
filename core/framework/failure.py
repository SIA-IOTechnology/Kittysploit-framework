from core.output_handler import print_error, print_status

from enum import Enum
import sys

class ProcedureError(Exception):
    """Exception raised when a procedure error occurs

    Accepts either a FailureType (preferred) or a plain string as the first
    argument. The second argument, when provided, is treated as the human
    message and overrides the default FailureType value.
    This keeps legacy single-argument usage working while supporting the
    common two-argument pattern used across modules.
    """
    def __init__(self, failure_or_message, message: str = None) -> None:
        if isinstance(failure_or_message, FailureType):
            self.failure_type = failure_or_message
            self.message = message or failure_or_message.value
        else:
            # Allow plain string / exception as first argument
            self.failure_type = None
            base = str(failure_or_message)
            self.message = f"{base}: {message}" if message else base

        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message

class ErrorDescription(ProcedureError):
    """Error description that can be set as an attribute on fail object"""
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)
    
    def __call__(self, raise_exception: bool = False):
        """
        When called, print error and optionally raise exception
        
        Args:
            raise_exception: If True, raise exception (for exploits). 
                           If False, just print message and return False (for auxiliary modules)
        """
        print_error(self.message)
        if raise_exception:
            raise self
        return False

class FailureType(Enum):
    """Failure types for the framework"""
    BadConfig = "Bad config file"
    Disconnect = "Disconnected"
    NotAccess = "No access"
    NoTarget = "Target not compatible"
    NotFound = "Not found"
    NotVulnerable = "The application response indicated it was not vulnerable"
    PayloadFailed = "The payload was delivered but no session was opened"
    TimeoutExpired = "The exploit triggered some form of timeout"
    Unknown = "Unknown error"
    UnReachable = "The network service was unreachable"
    UserInterrupt = "The exploit was interrupted by the user"
    NoSession = "Exploit completed but no session was opened"
    PortBusy = "Port is already busy"
    ProtocolError = "A protocol error occurred"
    ConfigurationError = "Configuration error"
    LoginFailed = "Login failed"  # Ajout direct des erreurs courantes
    AuthenticationError = "Authentication error"
    ConnectionError = "Connection error"
    CSRFGetFailed = "Failed to send CSRF GET request"
    CSRFPostFailed = "Failed to send CSRF POST request"

class Fail:
    
    def _split_camel_case(self, name: str) -> list:
        """Split camelCase or PascalCase into words"""
        import re
        return re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)', name)
    
    def __getattr__(self, name: str):
        try:
            failure = FailureType[name]
            message = failure.value
        except KeyError:
            message = ' '.join(word for word in self._split_camel_case(name))
        
        # Return a callable that prints error and returns False (for auxiliary modules)
        # For exploits, they can call it with raise_exception=True
        def fail_handler(raise_exception: bool = False):
            print_error(message)
            if raise_exception:
                raise ErrorDescription(message)
            return False
        
        return fail_handler
    


# Instance globale
fail = Fail()
