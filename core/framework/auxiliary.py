from core.framework.base_module import BaseModule, ModuleResult, normalize_module_result
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
            return normalize_module_result(self.run())
        except ProcedureError:
            return ModuleResult(success=False)
        except Exception:
            return ModuleResult(success=False)