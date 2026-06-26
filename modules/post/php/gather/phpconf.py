from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "Show PHP config",
		"description": "Show PHP config",
		"author": "KittySploit Team",
		"arch": Arch.PHP,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	},
	}	
		
	def run(self):
		output = self.cmd_execute("print_r(ini_get_all());")
		
		if output:
			print_info(output)
			return True
		else:
			print_warning("No PHP configuration information retrieved")
		
		return False