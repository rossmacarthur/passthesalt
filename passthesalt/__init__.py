import Crypto.Cipher.AES
import datetime
import hashlib
import json
import os
import pyperclip
import subprocess
import sys


__version__ = '1.0.1'


def passlify(bytes):
    """
    Create a password from a byte list.
    """
    lower = 'abcdefghijklmnopqrstuvwxyz'
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    numbers = '0123456789'
    symbols = '!@#$%^&*_+-='
    chars = lower + upper + numbers + symbols

    result = ''.join(chars[byte % len(chars)] for byte in bytes)

    # Attempt to make sure the password contains:
    #   a lowercase letter
    #   an uppercase letter
    #   a number
    #   a symbol (one of !@#$%^&*_+-=)
    for _ in range(256):
        if any(c in lower for c in result) and any(c in upper for c in result) and \
           any(c in numbers for c in result) and any(c in symbols for c in result):
            break
        bytes = [(byte + 1) % 256 for byte in bytes]
        result = ''.join(chars[byte % len(chars)] for byte in bytes)

    # Attempt to make sure the password starts with a letter
    for _ in range(len(result)):
        if result[0] in lower + upper:
            break
        result = result[1:] + result[0:1]

    return result


def encrypt(dictionary, master_key):
    """
    AES (CFB) encrypt 'dictionary' with 'master_key'.
    """
    key = hashlib.sha1(master_key.encode()).hexdigest()[:32]
    iv = os.urandom(16)
    aes_obj = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CFB, iv)
    return (iv + aes_obj.encrypt(json.dumps(dictionary))).hex()


def decrypt(encoded, master_key):
    """
    Decrypt an AES (CFB) encrypted dictionary.
    """
    key = hashlib.sha1(master_key.encode()).hexdigest()[:32]
    iv = bytes.fromhex(encoded[:32])
    aes_obj = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CFB, iv)
    return json.loads(aes_obj.decrypt(bytes.fromhex(encoded[32:])))


def pbkdf2_hash(password, salt=None):
    """
    PBKDF2 HMAC-SHA-256 hash a password (100 000 iterations)
    """
    if not salt:
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(salt)

    hash_ = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000,
        dklen=20
    )

    return salt.hex(), hash_.hex()


def generate(salt, master_key):
    """
    Generate a password from a master key and password description.
    """
    return passlify(hashlib.pbkdf2_hmac(
        'sha256',
        master_key.encode(),
        salt.encode(),
        2048,
        dklen=20
    ))


def to_clipboard(text, timeout=None):
    """
    Copy text to clipboard.
    """
    pyperclip.copy(text)
    if timeout:
        command = 'sleep {} && {} -c "import pyperclip;pyperclip.copy(\'\');"'.format(timeout, sys.executable)
        subprocess.Popen(command, stdin=subprocess.PIPE, shell=True)


class PassTheSalt:

    def __init__(self):
        self.config = dict()
        self.labels = dict()
        self.generatable = dict()
        self.encrypted = None

    def initialize(self, owner, master_password=None):
        self.config['owner'] = owner
        if master_password:
            salt, hash_ = pbkdf2_hash(master_password)
            self.config['master'] = {
                'hash': hash_,
                'salt': salt
            }

    def master_key(self, master_password):
        return self.config['owner'] + '|' + master_password

    def master_valid(self, master_password):
        if 'master' in self.config:
            _, hash_ = pbkdf2_hash(master_password, self.config['master']['salt'])
            return hash_ == self.config['master']['hash']
        else:
            return True

    def to_dict(self):
        return {k: v for k, v in vars(self).items() if v}

    def load(self, path):
        with open(path, 'r') as f:
            data = json.load(f)

        for key in data:
            setattr(self, key, data[key])

    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def exists(self, label):
        return label in self.labels

    def get(self, label, master_password):
        master_key = self.master_key(master_password)
        info = self.labels[label]
        if info['type'] == 'generatable':
            return generate(label + '|' + self.generatable[label], master_key)
        elif info['type'] == 'encrypted':
            return decrypt(self.encrypted, master_key)[label]

    def _store(self, label, type_):
        self.labels[label] = {
            'type': type_,
            'modified': datetime.date.today().strftime("%Y%m%d")
        }

    def _remove(self, label):
        del self.labels[label]

    def store_generatable(self, label, salt):
        self._store(label, 'generatable')
        self.generatable[label] = salt

    def remove_generatable(self, label):
        self._remove(label)
        del self.generatable[label]

    def store_encrypted(self, label, secret, master_password):
        master_key = self.master_key(master_password)
        if self.encrypted is not None:
            decrypted = decrypt(self.encrypted, master_key)
        else:
            decrypted = dict()
        self._store(label, 'encrypted')
        decrypted[label] = secret
        self.encrypted = encrypt(decrypted, master_key)

    def remove_encrypted(self, label, master_password):
        master_key = self.master_key(master_password)
        decrypted = decrypt(self.encrypted, master_key)
        self._remove(label)
        del decrypted[label]
        if not decrypted:
            self.encrypted = None
        else:
            self.encrypted = encrypt(decrypted, master_key)
