"""
Errors used in PassTheSalt.
"""


class Error(Exception):
    """
    A base error class.
    """

    def __init__(self, message):
        """
        Create a new Error.

        Args:
            message (Text): the error message.
        """
        super().__init__(message)
        self.message = message

    def __str__(self):
        """
        Return the error message.
        """
        return self.message


class LabelError(Error):
    """
    An error related to secret labels.
    """


class ContextError(Error):
    """
    An error related to the PassTheSalt context of a secret.
    """


class ConfigurationError(Error):
    """
    An error related to the PassTheSalt configuration.
    """


class SchemaError(Error):
    """
    An error related to loading and dumping a Schema.
    """


class RemoteError(Error):
    """
    An error related to accessing a remote store.
    """


class UnexpectedStatusCode(RemoteError):
    """
    Raised when an unexpected HTTP status code is received.
    """

    def __init__(self, message, code):
        """
        Create a new UnexpectedStatusCode error.

        Args:
            message (Text): the error message.
            code (int): the response status code.
        """
        super().__init__(message)
        self.code = code


class UnauthorizedAccess(UnexpectedStatusCode):
    """
    Raised when a 401 is received.
    """

    def __init__(self, message, code=401):
        """
        Create a new UnauthorizedAccess error.

        Args:
            message (Text): the error message.
            code (int): the response status code.
        """
        super().__init__(message, code)


class ConflictingTimestamps(UnexpectedStatusCode):
    """
    Raised when a 409 is received.
    """

    def __init__(self, message, code=409):
        """
        Create a new ConflictingTimestamps error.

        Args:
            message (Text): the error message.
            code (int): the response status code.
        """
        super().__init__(message, code)
