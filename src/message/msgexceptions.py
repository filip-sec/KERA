from abc import ABC, abstractproperty

"""
    Abstract class
"""

class FaultyNodeException(ABC, Exception):
    def __init__(self, message, error_name) -> None:
        self.error_name = error_name
        self.message = message
        super().__init__(self.message, self.error_name)

class NonfaultyNodeException(ABC, Exception):
    def __init__(self, message, error_name) -> None:
        self.error_name = error_name
        self.message = message
        super().__init__(self.message, self.error_name)

    
class ErrorInvalidFormat(FaultyNodeException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_FORMAT"
        super().__init__(self.message, self.error_name)

class ErrorInvalidHandshake(FaultyNodeException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_HANDSHAKE"
        super().__init__(self.message, self.error_name)

