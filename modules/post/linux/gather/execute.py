from kittysploit import *

class Module(Post, System):

    __info__ = {
        "name": "Linux Execute Command",
        "description": "Linux Execute Command",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }
    
    command = OptString("ls -la", "Command to execute", required=True)

    def run(self):

        result = self.cmd_execute(self.command)
        if result:
            print_info(result)
            return True
        else:
            return False