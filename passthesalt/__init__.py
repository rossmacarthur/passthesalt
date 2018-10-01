"""
PassTheSalt is a deterministic password generation and password storage system.
"""

from .core import Algorithm, Config, Encrypted, Generatable, Login, Master, PassTheSalt, Secret
from .error import (ConfigurationError, ConflictingTimestamps, ContextError, Error, LabelError,
                    RemoteError, SchemaError, UnauthorizedAccess, UnexpectedStatusCode)
from .remote import Remote, Stow


__all__ = ['Algorithm', 'Config', 'ConfigurationError', 'ConflictingTimestamps',
           'ContextError', 'Encrypted', 'Error', 'Generatable', 'LabelError',
           'Login', 'Master', 'PassTheSalt', 'Remote', 'RemoteError', 'SchemaError',
           'Secret', 'Stow', 'UnauthorizedAccess', 'UnexpectedStatusCode']

__version__ = '3.0.0'
