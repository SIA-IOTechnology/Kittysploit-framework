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
            result = self.run()
            if result is None:
                return True
            return bool(result)
        except ProcedureError:
            return False
        except Exception:
            return False