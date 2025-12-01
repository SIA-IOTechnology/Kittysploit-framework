from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "Check Disable Functions",
		"description": "Check Disable Functions",
		"arch": Arch.PHP,
	}	
		
	def run(self):
		print_status("Disable Functions :")
		output = self.cmd_execute("var_dump(explode(',',ini_get('disable_functions')));")
		if output:
			print_info(output)
		else:
			print_warning("No disabled functions found or unable to retrieve information")
		return True
