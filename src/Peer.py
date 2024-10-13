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
                raise ValueError(f"Invalid host or IP: {host_str}")

    def __str__(self) -> str:
        return f"{self.host_formated}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host == o.host and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"
    
    def validate_hostname(host_str) -> bool:
        """
        Validates a given hostname string.
    
        A valid hostname:
        - Has a length of 253 characters or less.
        - Is composed of labels separated by dots.
        - Each label is between 1 and 63 characters long.
        - Each label contains only alphanumeric characters and hyphens.
        - Each label does not start or end with a hyphen.
        """
        # Check if hostname is valid
        if len(host_str) > 253:
            return False
        
        # Split by dots and validate each label
        labels = host_str.split('.')
        for label in labels:
            if len(label) == 0 or len(label) > 63:
                return False
            if not re.match("^[a-zA-Z0-9-]*$", label):
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        return True


