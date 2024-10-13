import ipaddress
import re

class Peer:
    def __init__(self, host_str, port: int):
        self.port = port
        self.host_formated = ''
        self.host = ''
        
        # Validate and populate properties
        try:
            ip = ipaddress.ip_address(host_str)
            self.host = str(ip)
            self.host_formated = str(ip)
        
        except ValueError:
            if self.validate_hostname(host_str):
                self.host = host_str
                self.host_formated = host_str
            else:
                raise ValueError(f"Invalid host: {host_str}")

    def __str__(self) -> str:
        return f"{self.host_formated}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host == o.host and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"

    @staticmethod
    def validate_hostname(host_str: str) -> bool:
        """
        Validates if the provided string is a valid hostname.
        A valid hostname:
        - Contains only alphanumeric characters and hyphens.
        - Each label (parts separated by dots) is between 1 and 63 characters.
        - The entire hostname does not exceed 255 characters.
        """
        if len(host_str) > 255:
            return False
        # Remove the trailing dot if present
        if host_str[-1] == ".":
            host_str = host_str[:-1]
        # Split the hostname into labels
        labels = host_str.split(".")
        # Define a regular expression pattern for a valid label
        pattern = re.compile(r"^[a-zA-Z0-9-]{1,63}$")
        # Check each label against the pattern
        return all(pattern.match(label) for label in labels)
