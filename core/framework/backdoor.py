from core.framework.base_module import BaseModule
from core.framework.failure import ProcedureError, FailureType
from core.output_handler import print_warning

class Backdoor(BaseModule):
    
    TYPE_MODULE = "backdoor"
    
    def __init__(self):
        super().__init__()
    
    def check(self):
        raise NotImplementedError("Backdoor modules must implement the check() method")

    def run(self):
        raise NotImplementedError("Backdoor modules must implement the run() method")
    
    def _exploit(self):
        try:
            self.run()
            print_warning(f"Use responsibly and only on authorized systems!")
        except ProcedureError as e:
            return False
        except Exception as e:
            return False
        return True