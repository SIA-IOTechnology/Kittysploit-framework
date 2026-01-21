from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort, OptInt, OptChoice, OptBool
from core.output_handler import print_success, print_status, print_error, print_info, print_warning

class ExeCompiler(BaseModule):

    def __init__(self, framework=None):
        super().__init__(framework)

    def generate_exe(self, source_code: str, output_path: str):
        return self.framework.payload.generate_exe(source_code, output_path)
    
    def generate_elf(self, source_code: str, output_path: str):
        return self.framework.payload.generate_elf(source_code, output_path)
    
    def generate_pe(self, source_code: str, output_path: str):
        return self.framework.payload.generate_pe(source_code, output_path)
    
    def generate_shellcode(self, source_code: str, output_path: str):
        return self.framework.payload.generate_shellcode(source_code, output_path)
    
    def generate_payload(self, source_code: str, output_path: str):
        return self.framework.payload.generate_payload(source_code, output_path)