#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""UART bind listener — opens a serial port session for hardware post modules."""

from kittysploit import *
from lib.protocols.hardware.uart_client import UartClient
from lib.protocols.hardware.uart_proxy import list_serial_ports


class Module(Listener):
    __info__ = {
        "name": "UART Listener",
        "description": (
            "Opens a serial UART device (USB-TTL, console header, etc.) and creates "
            "a session for hardware gather/manage post modules"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.UART,
        "protocol": "uart",
        "dependencies": ["serial"],
        "references": [
            "https://pyserial.readthedocs.io/",
            "https://attack.mitre.org/techniques/T0842/",
        ],
    }

    port = OptString("/dev/ttyUSB0", "Serial device path (e.g. /dev/ttyUSB0, COM3)", True)
    baudrate = OptInteger(115200, "Baud rate", True)
    bytesize = OptInteger(8, "Data bits (5-8)", False)
    parity = OptChoice("N", "Parity", False, choices=["N", "E", "O", "M", "S"])
    stopbits = OptString("1", "Stop bits (1, 1.5, 2)", False)
    xonxoff = OptBool(False, "Software flow control (XON/XOFF)", False, advanced=True)
    rtscts = OptBool(False, "Hardware RTS/CTS flow control", False, advanced=True)
    dsrdtr = OptBool(False, "Hardware DSR/DTR flow control", False, advanced=True)
    list_ports = OptBool(False, "List available serial ports then exit", False)

    def run(self):
        try:
            import serial  # noqa: F401
        except ImportError:
            print_error("pyserial is required but not installed")
            print_info("Install it with: pip install pyserial")
            return False

        if bool(self.list_ports):
            print_status("Available serial ports:")
            ports = list_serial_ports(verbose=True)
            if not ports:
                print_warning("No serial ports found")
            return False

        device = str(self.port or "").strip()
        baud = int(self.baudrate or 115200)
        timeout = float(self.timeout or 1)
        try:
            stopbits = float(str(self.stopbits or "1"))
        except ValueError:
            print_error(f"Invalid stopbits: {self.stopbits}")
            return False

        print_status(f"Opening UART {device} @ {baud} baud...")
        client = UartClient(
            port=device,
            baudrate=baud,
            bytesize=int(self.bytesize or 8),
            parity=str(self.parity or "N"),
            stopbits=stopbits,
            timeout=timeout,
            write_timeout=timeout,
            xonxoff=bool(self.xonxoff),
            rtscts=bool(self.rtscts),
            dsrdtr=bool(self.dsrdtr),
        )
        if not client.connect():
            print_error(f"Failed to open serial port {device}")
            print_info("Tip: set list_ports=true to enumerate devices")
            return False

        print_success(f"UART session established on {device} @ {baud}")
        print_info(f"  Config: {client.bytesize}{client.parity}{client.stopbits}")

        additional_data = {
            "device": device,
            "port_name": device,
            "serial_port": device,
            "baudrate": baud,
            "baud": baud,
            "bytesize": client.bytesize,
            "parity": client.parity,
            "stopbits": client.stopbits,
            "timeout": timeout,
            "xonxoff": client.xonxoff,
            "rtscts": client.rtscts,
            "dsrdtr": client.dsrdtr,
            "protocol": "uart",
            "platform": "hardware",
        }
        # host = device path, port field reused for baud (numeric session port)
        return (client, device, baud, additional_data)

    def shutdown(self):
        return True
