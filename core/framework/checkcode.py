from core.output_handler import print_success

class SuccessDescriptor:

    def __init__(self, message = "Success") -> None:

        self.message = message
    
    def __get__(self, instance, owner):
        print_success(self.message)

class Vulnerable:

    SUCCESS = SuccessDescriptor("The target is vulnerable")
    APPEARS_VULNERABLE = SuccessDescriptor("The target appears to be vulnerable")
    VULNERABLE = SuccessDescriptor("The target is vulnerable")

    def __init__(self, message = "success") -> None:
        SuccessDescriptor(message)