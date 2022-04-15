from typing import Optional


class KeysNotFound(Exception):
    """Exception: file does not contain the required keys"""

    def __init__(self, message: Optional[str] = "file does not contain the required keys"):
        self.message = message
        super().__init__(self.message)


class FileLocationNotValid(IOError):
    """Exception: File is not found at the given location"""

    def __init__(self, message: Optional[str] = "File is not found at the given location"):
        self.message = message
        super().__init__(self.message)


class InvalidMode(Exception):
    """Exception: invalid mode. It should either be alice or bob"""

    def __init__(self, message: Optional[str] = "Mode should either be alice or bob"):
        self.message = message
        super().__init__(self.message)


class OneTimeKeysListEmpty(IndexError):
    """Exception: list of one time keys are empty"""

    def __init__(self, message: Optional[str] = "list of one time keys are empty"):
        self.message = message
        super().__init__(self.message)
