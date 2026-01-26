from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "MySQL Database Connection",
		"description": "Connect to MySQL database and execute SQL queries",
		"author": "KittySploit Team",
		"session_type": SessionType.PHP,
		"arch": Arch.PHP,
	}	

	host = OptString("localhost", "MySQL host", True)
	port = OptPort(3306, "MySQL port", True)
	username = OptString("root", "MySQL username", True)
	password = OptString("", "MySQL password", False)
	database = OptString("", "Database name (optional)", False)
	query = OptString("SHOW DATABASES;", "SQL query to execute", False)

	def run(self):
		try:
			# Helper function to escape strings for PHP
			def escape_php_string(s):
				# Escape backslashes and single quotes
				return s.replace('\\', '\\\\').replace("'", "\\'")
			
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
			
			# Escape strings for PHP
			host_escaped = escape_php_string(self.host)
			user_escaped = escape_php_string(self.username)
			pass_escaped = escape_php_string(self.password)
			db_escaped = escape_php_string(self.database)
			query_escaped = escape_php_string(self.query) if self.query else ""
			
			# Build connection code based on available extension
			if ext_type == 'mysqli':
				# Use mysqli extension
				connect_code = f"""
$host = '{host_escaped}';
$port = {self.port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';

$mysqli = @new mysqli($host, $user, $pass, $db, $port);
if ($mysqli->connect_error) {{
	echo 'Connection failed: ' . $mysqli->connect_error;
	exit;
}}
echo 'Connected successfully' . PHP_EOL;
"""
			else:
				# Use legacy mysql extension
				connect_code = f"""
$host = '{host_escaped}';
$port = {self.port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';

$link = @mysql_connect($host . ':' . $port, $user, $pass);
if (!$link) {{
	echo 'Connection failed: ' . mysql_error();
	exit;
}}
echo 'Connected successfully' . PHP_EOL;
if ($db) {{
	@mysql_select_db($db, $link);
}}
"""
			
			# Execute connection
			connect_result = self.cmd_execute(connect_code)
			if not connect_result or 'Connection failed' in connect_result:
				raise ProcedureError(FailureType.NotAccess, f"Failed to connect to MySQL: {connect_result}")
			
			print_success("Connected to MySQL server")
			
			# Execute query
			if self.query:
				if ext_type == 'mysqli':
					query_code = f"""
$host = '{host_escaped}';
$port = {self.port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';
$query = '{query_escaped}';

$mysqli = @new mysqli($host, $user, $pass, $db, $port);
if ($mysqli->connect_error) {{
	echo 'Connection failed: ' . $mysqli->connect_error;
	exit;
}}

$result = @$mysqli->query($query);
if (!$result) {{
	echo 'Query failed: ' . $mysqli->error;
	exit;
}}

if ($result === true) {{
	echo 'Query executed successfully (no result set)' . PHP_EOL;
}} else {{
	// Fetch results
	$rows = array();
	while ($row = $result->fetch_assoc()) {{
		$rows[] = $row;
	}}
	
	if (empty($rows)) {{
		echo 'No results' . PHP_EOL;
	}} else {{
		// Print column headers
		$headers = array_keys($rows[0]);
		echo implode(' | ', $headers) . PHP_EOL;
		echo str_repeat('-', 80) . PHP_EOL;
		
		// Print rows
		foreach ($rows as $row) {{
			$values = array();
			foreach ($headers as $header) {{
				$value = isset($row[$header]) ? $row[$header] : '';
				$value = is_null($value) ? 'NULL' : $value;
				$values[] = $value;
			}}
			echo implode(' | ', $values) . PHP_EOL;
		}}
	}}
	$result->free();
}}
$mysqli->close();
"""
				else:
					query_code = f"""
$host = '{host_escaped}';
$port = {self.port};
$user = '{user_escaped}';
$pass = '{pass_escaped}';
$db = '{db_escaped}';
$query = '{query_escaped}';

$link = @mysql_connect($host . ':' . $port, $user, $pass);
if (!$link) {{
	echo 'Connection failed: ' . mysql_error();
	exit;
}}
if ($db) {{
	@mysql_select_db($db, $link);
}}

$result = @mysql_query($query, $link);
if (!$result) {{
	echo 'Query failed: ' . mysql_error($link);
	mysql_close($link);
	exit;
}}

if ($result === true) {{
	echo 'Query executed successfully (no result set)' . PHP_EOL;
}} else {{
	// Fetch results
	$rows = array();
	while ($row = mysql_fetch_assoc($result)) {{
		$rows[] = $row;
	}}
	
	if (empty($rows)) {{
		echo 'No results' . PHP_EOL;
	}} else {{
		// Print column headers
		$headers = array_keys($rows[0]);
		echo implode(' | ', $headers) . PHP_EOL;
		echo str_repeat('-', 80) . PHP_EOL;
		
		// Print rows
		foreach ($rows as $row) {{
			$values = array();
			foreach ($headers as $header) {{
				$value = isset($row[$header]) ? $row[$header] : '';
				$value = is_null($value) ? 'NULL' : $value;
				$values[] = $value;
			}}
			echo implode(' | ', $values) . PHP_EOL;
		}}
	}}
	mysql_free_result($result);
}}
mysql_close($link);
"""
				
				query_result = self.cmd_execute(query_code)
				if query_result:
					print_info("Query result:")
					print_info(query_result)
				else:
					print_warning("No output from query")
			
			return True
			
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error connecting to MySQL: {e}")

