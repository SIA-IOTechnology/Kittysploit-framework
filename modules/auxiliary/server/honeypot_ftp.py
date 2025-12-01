from kittysploit import *
import socket
import threading

class Module(Auxiliary, Tcp_server):

    __info__ = {
        'name': 'Honeypot FTP server',
        'description': 'Honeypot FTP server',
        'author': 'KittySploit Team',
    }

    ftp_banner = "220 Welcome to Fake FTP Server"

    def run(self):
        try:
            honeypot = Tcp_server()
            server = honeypot.server_tcp("0.0.0.0", 21, timeout=10)
            if not server:
                print_error("Failed to start TCP server.")
                return

            print_success("Starting FTP Honeypot on 0.0.0.0:21")


            client, address = server.listen()
            if client and address:
                print_status(f"Connection received from {address[0]}:{address[1]}")
                self.handle_client(client, address)
            else:
                print_warning("No client connection received.")

        except Exception as e:
            print_error(f"Failed to run the FTP honeypot: {str(e)}")


    def handle_client(self, client, address):
        """
        Handle interactions with the client.
        """
        try:
            if client:
                print_status(f"Sending banner to {address}")
                client.send(self.ftp_banner.encode() + b"\r\n")
                self.collect_client_info(client, address)
                
        except BrokenPipeError:
            print_warning("Connection was broken while sending the banner.")
            return

    def collect_client_info(self, client, address):
        print_success(f"Client IP: {address[0]}")
        print_success(f"Client Port: {address[1]}")

        try:
            reverse_dns = socket.gethostbyaddr(address[0])
            print_success(f"Client Hostname (Reverse DNS): {reverse_dns[0]}")
        except socket.herror:
            print_warning("Unable to resolve hostname for the client.")
