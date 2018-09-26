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
