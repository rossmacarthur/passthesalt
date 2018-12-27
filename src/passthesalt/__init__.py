"""
PassTheSalt is a deterministic password generation and password storage system.
"""

from passthesalt.core import (
    Algorithm, Config, Encrypted, Generatable, Login, Master, PassTheSalt, Secret
)


__all__ = [
    'Algorithm',
    'Config',
    'Encrypted',
    'Generatable',
    'Login',
    'Master',
    'PassTheSalt',
    'Secret',
    'error',
    'remote'
]
__title__ = 'passthesalt'
__version__ = '3.0.0'
__url__ = 'https://github.com/rossmacarthur/passthesalt'
__author__ = 'Ross MacArthur'
__author_email__ = 'ross@macarthur.io'
__license__ = 'MIT'
__description__ = 'Deterministic password generation and password storage.'
