"""
Errors used in PassTheSalt.
"""


class PassTheSaltError(Exception):
    """
    A base error class.
    """

    def __init__(self, message):
        """
        Create a new PassTheSaltError.

        Args:
            message (str): the error message.
        """
        super().__init__(message)

    @property
    def message(self):
        """
        Return the error message.
        """
        return self.args[0]

    def __str__(self):
        """
        Return a string representation of this PassTheSaltError.
        """
        return self.message

    def __repr__(self):
        """
        Return the canonical string representation of this PassTheSaltError.
        """
        return (
            f'{self.__class__.__module__}.{self.__class__.__name__}({self.message!r})'
        )


class LabelError(PassTheSaltError):
    """
    An error related to secret labels.
    """


class ContextError(PassTheSaltError):
    """
    An error related to the PassTheSalt context of a secret.
    """


class ConfigurationError(PassTheSaltError):
    """
    An error related to the PassTheSalt configuration.
    """


class RemoteError(PassTheSaltError):
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
            message (str): the error message.
            code (int): the response status code.
        """
        super().__init__(message)
        self.code = code

    def __repr__(self):
        """
        Return the canonical string representation of this SerdeError.
        """
        return (
            f'{self.__class__.__module__}.{self.__class__.__name__}'
            f'({self.message!r}, code={self.code!r})'
        )


class UnauthorizedAccess(UnexpectedStatusCode):
    """
    Raised when a 401 is received.
    """

    def __init__(self, message, code=401):
        """
        Create a new UnauthorizedAccess error.

        Args:
            message (str): the error message.
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
            message (str): the error message.
            code (int): the response status code.
        """
        super().__init__(message, code)
