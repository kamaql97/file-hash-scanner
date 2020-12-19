"""
Palo Alto Networks Assignement - Kamal Qarain

Custom exceptions raised when specific errors occur
"""

class InvalidFileHashError(Exception):
    """
    Exception raised when the entered string is not a valid
    MD5, SHA-1, or SHA-256 hash

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message='Enter a valid file hash (MD5, SHA-1, or SHA-256)'):
        self.message = message
        super().__init__(self.message)


class APIKeyNotFoundError(Exception):
    """
    Exception raised when api is not found in environmental variables

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message='Could not find Environmental variable'):
        self.message = message
        super().__init__(self.message)


class VirusTotalUnreachableError(Exception):
    """
    Exception raised when the service cannot be reached
    (client not online or server down)

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message='Could not connect to VirusTotal'):
        self.message = message
        super().__init__(self.message)


class UnexpectedResponseError(Exception):
    """
    Exception raised the reponse code is not HTTP 200 [OK]

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message='Returned unexpected response, check API key'):
        self.message = message
        super().__init__(self.message)
