from abc import ABC, abstractproperty

"""
    Abstract class
"""
class NodeException(ABC, Exception):
    def __init__(self, message, error_name) -> None:
            self.error_name = error_name
            self.message = message
            super().__init__(self.message, self.error_name)

class FaultyNodeException(NodeException):
    def __init__(self, message, error_name) -> None:
        self.error_name = error_name
        self.message = message
        super().__init__(self.message, self.error_name)

class NonfaultyNodeException(NodeException):
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

class ErrorInvalidTxSignature(FaultyNodeException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_TX_SIGNATURE"
        super().__init__(self.message, self.error_name)

class  ErrorInvalidTxConservation(FaultyNodeException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_TX_CONSERVATION"
        super().__init__(self.message, self.error_name)

class ErrorInvalidTxOutpoint(FaultyNodeException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_TX_OUTPOINT"
        super().__init__(self.message, self.error_name)

class ErrorUnknownObject(NonfaultyNodeException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "UNKNOWN_OBJECT"
        super().__init__(self.message, self.error_name)
