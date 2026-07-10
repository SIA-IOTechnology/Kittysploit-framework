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
            return bool(self.run())
        except ProcedureError:
            return False
        except Exception:
            return False
        finally:
            print_warning("Use responsibly and only on authorized systems!")
