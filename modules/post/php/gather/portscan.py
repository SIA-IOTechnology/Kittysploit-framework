from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "PHP Port Scanner",
		"description": "PHP Port Scanner",
		"arch": Arch.PHP,
	}	
	
	target = OptString("127.0.0.1", "host", True)
	port_min = OptInteger(21, "port min", True)
	port_max = OptInteger(1000, "port max", True)
		
	def run(self):
		data = f"""
		$ports = range({self.port_min}, {self.port_max});
		shuffle($ports);

		$result = "";
		foreach ($ports as $port) {{
			$fp = @fsockopen("{self.target}", $port, $errno, $errstr, 2);
			if ($fp !== FALSE) {{
				@fclose($fp);
			$result .= "open ".$port."\r\n";
			}}
		}}
		echo $result;	
		"""
		print_status(self.target)
		print_status("=============")
		print_info(self.php_eval(data, 30))
		return True