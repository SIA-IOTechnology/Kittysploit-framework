from kittysploit import *

class Module(Post):

	__info__ = {
		"name": "List running processes",
		"description": "List running processes",
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
		output = self.cmd_execute("""
class UIDMap {
	private $map = array();
	public function __construct() {
		$lines = @explode(PHP_EOL, file_get_contents('/etc/passwd'));
		if (!$lines) return;
		foreach ($lines as $line) {
			$els = explode(':', $line);
			$uname = $els[0];
			if (strlen($uname) > 8) $uname = substr($uname, 0, 7) . '+';
			$this->map[$els[2]] = $uname;
		}
	}
	public function getUserName($uid) {
		$uname = $this->map[$uid];
		if (!$uname) return $uid;
		return $uname;
	}
}
function getTtyName($ttynr) {
	$major = ($ttynr >> 8) & 0xffffffff ;
	$minor = $ttynr & 0xff;
	if ($major === 4) {
		if ($minor < 64) return 'tty'.$minor;
		return 'ttyS'.(255 - $minor);
	} else if ($major >= 136 && $major <=143) {
		return 'pts/'.$minor;
	}
	// unsupported tty
	return '?';
}
function getProcInfo($procpath, $pid) {
	global $uidmap;
	$info = array(
		'UID'   => '?',
		'PID'   => '?',
		'PPID'  => '?',
		'STIME' => '?',
		'TTY'   => '?',
		'TIME'  => '?',
		'CMD'   => '?'
	);
	$content = @file_get_contents(join(DIRECTORY_SEPARATOR, array($procpath, $pid, 'stat')));
	if (!$content) return $info;
	$stats = explode(' ', $content);
	$info['PID']  = $stats[0];
	$info['PPID'] = $stats[3];
	$curtime = time();
	$stime = @filemtime(join(DIRECTORY_SEPARATOR, array($procpath, $pid)));
	if (date('j', $curtime) === date('j', $stime)) {
		$info['STIME'] = date('H:i', $stime);
	} else {
		$info['STIME'] = date('Md', $stime);
	}
	$time = $curtime - $stime;
	$hours        = floor($time / 3600);
	$minutes      = floor(($time % 3600) / 60);
	$seconds      = $time % 60;
	$info['TIME'] = sprintf("%'.02d:%'.02d:%'.02d", $hours, $minutes, $seconds);
	$info['TTY'] = getTtyName($stats[6]);
	$cmd = @file_get_contents(join(DIRECTORY_SEPARATOR, array($procpath, $pid, 'cmdline')));
	if ($cmd && strlen($cmd) > 0) {
		$cmd = @str_replace("\x00", ' ', $cmd);
	} else {
		$cmd = @str_replace('(', '[', str_replace(')', ']', $stats[1]));
	}
	$info['CMD'] = $cmd;
	$content = @explode(PHP_EOL, file_get_contents(join(DIRECTORY_SEPARATOR, array($procpath, $pid, 'status'))));
	foreach ($content as $line) {
		$els = explode("\t", $line);
		if ($els[0] !== 'Uid:') continue;
		$info['UID'] = $uidmap->getUserName($els[1]);
		break;
	}
	return $info;
}
function main() {
	global $uidmap;
	$procpath = '/proc';
	if (!file_exists('/proc')) {
		$lines = @explode(PHP_EOL, file_get_contents('/etc/mtab'));
		if (!$lines) {
			print('Unable to list processes.' . PHP_EOL);
			return;
		}
		foreach ($lines as $line) {
			$els = explode(' ', $line);
			if ($els[0] !== 'proc') continue;
			$procpath = $els[1];
		}
		if ($procpath === '/proc') {
			print('Unable to list processes.' . PHP_EOL);
			return;
		}
	}
	$uidmap = new UIDMap();
	$pids = @scandir($procpath);
	$format = '%-8s %5s %5s %5s %-8s %10s %s' . PHP_EOL;
	printf($format, 'UID', 'PID', 'PPID', 'STIME', 'TTY', 'TIME', 'CMD');
	foreach ($pids as $pid) {
		if (!is_numeric($pid)) continue;
		$proc = getProcInfo($procpath, $pid);
		printf($format, $proc['UID'], $proc['PID'], $proc['PPID'], $proc['STIME'], $proc['TTY'], $proc['TIME'], $proc['CMD']);
	}
}
main();
""")
		if output:
			print_info(output)
		else:
			print_warning("Unable to list processes or no output returned")
		return True