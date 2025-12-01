from core.framework.base_module import BaseModule
from core.output_handler import print_info, print_success, print_error

class Encoder(BaseModule):

    TYPE_MODULE = "encoder"

    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "encoder"

    def encode(self, payload):
        """Encode the payload"""
        raise NotImplementedError("Encoder modules must implement the encode() method")
    
    def run(self):
        """Run the encoder"""
        print_error("Encoder module cannot be run directly")
        return False