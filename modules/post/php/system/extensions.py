from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "Collect PHP and webserver extension list",
		"description": "Collect PHP and webserver extension list",
		"arch": Arch.PHP,
	}	
		
	def run(self):
		print_status("Php extensions :")
		output = self.cmd_execute("""
$f='get_loaded_extensions';
if(function_exists($f)&&is_callable($f))
	foreach($f() as $o) print($o.PHP_EOL);
""")
		if output:
			print_info(output)
		else:
			print_warning("No PHP extensions found or function not available")
		
		print_status("Apache modules :")
		output = self.cmd_execute("""
$f='apache_get_modules';
if(function_exists($f)&&is_callable($f))
	foreach($f() as $o) print($o.PHP_EOL);
""")
		if output:
			print_info(output)
		else:
			print_warning("No Apache modules found or function not available")
		
		return True