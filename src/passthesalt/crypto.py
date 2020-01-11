"""
Cryptographic utilities used in PassTheSalt.
"""

import json
import os
import string
from base64 import urlsafe_b64encode
from binascii import hexlify, unhexlify
from hashlib import sha256

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def pbkdf2_hash_bytes(password, salt, iterations=2048, length=20):
    """
    PBKDF2 HMAC-SHA-256 hash a password.

    Args:
        password (str): the password to hash.
        salt (bytes): the salt for the hash.
        iterations (int): the number of PBKDF2 iterations.

    Returns:
        bytes: the hash.
    """
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    ).derive(password.encode())


def pbkdf2_hash(password, salt=None, iterations=100000):
    """
    PBKDF2 HMAC-SHA-256 hash a password.

    Args:
        password (str): the password to hash.
        salt (str): the salt for the hash.
        iterations (int): the number of PBKDF2 iterations.

    Returns:
        str: the hash as a hex string.
    """
    if salt is None:
        salt = hexlify(os.urandom(20)).decode()

    hash_bytes = pbkdf2_hash_bytes(password, unhexlify(salt), iterations=iterations)
    hash = hexlify(hash_bytes).decode()

    return salt, hash


def generate_key(master_key):
    """
    Generate a Fernet key from the master key.

    Args:
        master_key (str): the master key.

    Returns:
        str: 32 url-safe base64-encoded bytes.
    """
    return urlsafe_b64encode(sha256(master_key.encode()).digest())


def encrypt(d, master_key):
    """
    Encrypt a dictionary with a master key.

    Args:
        d (dict): the dictionary to encrypt.
        master_key (str): the master key.

    Returns:
        str: the encrypted dictionary as a hex string.
    """
    key = generate_key(master_key)
    fernet = Fernet(key)
    data = json.dumps(d, sort_keys=True).encode()
    encrypted = fernet.encrypt(data)
    return hexlify(encrypted).decode()


def decrypt(s, master_key):
    """
    Decrypt an encrypted dictionary with the master key.

    Args:
        s (str): the encrypted hexstring.
        master_key (str): the master key.

    Returns:
        dict: the decrypted dictionary.
    """
    key = generate_key(master_key)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(unhexlify(s))
    return json.loads(decrypted.decode())


def passlify_legacy(b):
    """
    Create a legacy password from a bytes object.

    WARNING: This method is broken. It is kept so that legacy passwords from
    older versions of PassTheSalt can still be generated.

    Args:
        b (bytes): the bytes object.

    Returns:
        str: the password.
    """

    def shiftlify(b, chars, shift=0):
        b = [(byte + shift) % 256 for byte in b]
        return ''.join(chars[byte % len(chars)] for byte in b)

    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        '!@#$%^&*_+-=',
    ]
    chars = ''.join(groups)
    password = shiftlify(b, chars)

    # This make sure the password contains something in each group
    for _ in range(256):
        if all(any(c in group for c in password) for group in groups):
            break

        password = shiftlify(b, chars, shift=1)

    # Attempt to make sure the password starts with a letter
    for _ in range(len(password)):
        if password[0] in string.ascii_letters:
            break

        password = password[1:] + password[0:1]

    return password


def passlify(
    b, lowers=True, uppers=True, digits=True, extras='!@#$%^&*_+-=', startswith=None
):
    """
    Create a password from a bytes object.

    This method attempts to make sure the password contains at least one
    lowercase letter, uppercase letter, a number and a symbol. It also shifts
    the password until the first character is a letter.

    Args:
        b (bytes): the bytes object.
        lowers (bool): use lowercase letters.
        uppers (bool): use uppercase letters.
        digits (bool): use digits.
        extras (str): extra symbols to use.
        startswith (str): attempt to make sure the password starts with one of
            these chracters.

    Returns:
        str: the password.
    """
    groups = []

    if lowers:
        groups.append(string.ascii_lowercase)
    if uppers:
        groups.append(string.ascii_uppercase)
    if digits:
        groups.append(string.digits)
    if extras:
        groups.append(extras)
    if startswith is None:
        startswith = string.ascii_letters

    chars = ''.join(groups)

    def shift(i):
        return 7 * ((i + 1) ** 2 + (i + 1)) / 2

    def rotate(b):
        b = [int(byte + shift(i)) % 256 for i, byte in enumerate(b)]
        return bytes(b[1:] + b[0:1])

    # This make sure the password contains something in each group
    for _ in range(256):
        password = ''.join(chars[byte % len(chars)] for byte in b)

        if all(any(c in group for c in password) for group in groups):
            break

        b = rotate(b)

    # Attempt to make sure the password starts with a letter
    for _ in range(len(password)):
        if password[0] in startswith:
            break

        password = password[1:] + password[0:1]

    return password


def generate(salt, master_key, version=None, length=None):
    """
    Generate a password from a salt and master key.

    Args:
        salt (str): the salt.
        master_key (str): the master key.
        version (int): the generation algorithm version.

    Returns:
        str: the generated secret.
    """
    if length is None:
        length = 20

    b = pbkdf2_hash_bytes(master_key, salt=salt.encode(), length=length)

    if version == 1:
        return passlify(b)

    return passlify_legacy(b)
