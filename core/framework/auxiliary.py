from core.framework.base_module import BaseModule
from core.framework.failure import ProcedureError, FailureType

class Auxiliary(BaseModule):
    
    TYPE_MODULE = "auxiliary"

    def __init__(self):
        super().__init__()
    
    def check(self):
        raise NotImplementedError("Auxiliary modules must implement the check() method")

    def run(self):
        raise NotImplementedError("Auxiliary modules must implement the run() method")
    
    def _exploit(self):
        try:
            self.run()
            return True
        except ProcedureError as e:
            return False
        except Exception as e:
            return False