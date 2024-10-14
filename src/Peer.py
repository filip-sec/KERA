import ipaddress
import re

class Peer:
    def __init__(self, host_str, port: int):
        self.port = port
        self.host_formated = ''
        self.host = ''
        
        # Validate and populate properties
        if self.validate_peer(host_str, port):
            try:
                ip = ipaddress.ip_address(host_str)
                self.host = str(ip)
                self.host_formated = str(ip)
            except ValueError:
                self.host = host_str
                self.host_formated = host_str
        else:
            raise ValueError(f"Invalid host or IP: {host_str}")

    def __str__(self) -> str:
        return f"{self.host_formated}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host == o.host and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"

    @staticmethod
    def validate_peer(host: str, port: int) -> bool:
        """
        Validates a given peer string in the form of host:port.

        A valid peer:
        - Has a host which is either a valid DNS entry or a syntactically valid IPv4 address.
        - Has a port which is a decimal number in the range [1, 65535].

        A valid DNS entry:
        - Matches the regular expression [a-zA-Z\d\.\-\_]{3,50}.
        - Contains at least one dot which is not at the first or last position.
        - Contains at least one letter (a-z or A-Z).

        Args:
            host (str): The host string to validate.
            port (int): The port number to validate.

        Returns:
            bool: True if the peer is valid, False otherwise.
        """
        
        # Remove quotes from the beginning and end of the host string
        host = host.strip('"')
        
        # Validate the port
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False

        # Validate the host
        if re.match(r'^[a-zA-Z\d\.\-\_]{3,50}$', host):
            if host.count('.') >= 1 and not (host.startswith('.') or host.endswith('.')):
                if re.search(r'[a-zA-Z]', host):
                    return True

        # Validate IPv4 address
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ipv4_pattern.match(host):
            parts = host.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True

        return False