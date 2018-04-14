from __future__ import absolute_import, division, print_function, unicode_literals
from binascii import unhexlify, hexlify as hexlify_
import Crypto.Cipher.AES
import base64
import datetime
import dateutil.parser
import hashlib
import json
import os
import pyperclip
import requests
import subprocess
import sys


__version__ = '2.2.1'


if sys.version_info < (3, 0):
    def shiftlify(bytes, chars, shift=0):
        bytes = [(ord(byte) + shift) % 256 for byte in bytes]
        return ''.join(chars[byte % len(chars)] for byte in bytes)
else:
    def shiftlify(bytes, chars, shift=0):
        bytes = [(byte + shift) % 256 for byte in bytes]
        return ''.join(chars[byte % len(chars)] for byte in bytes)


def passlify(bytes):
    """
    Create a password from a byte list.
    """
    lower = 'abcdefghijklmnopqrstuvwxyz'
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    numbers = '0123456789'
    symbols = '!@#$%^&*_+-='
    chars = lower + upper + numbers + symbols

    result = shiftlify(bytes, chars)

    # Attempt to make sure the password contains:
    #   a lowercase letter
    #   an uppercase letter
    #   a number
    #   a symbol (one of !@#$%^&*_+-=)
    for _ in range(256):
        if any(c in lower for c in result) and any(c in upper for c in result) and \
           any(c in numbers for c in result) and any(c in symbols for c in result):
            break
        result = shiftlify(bytes, chars, shift=1)

    # Attempt to make sure the password starts with a letter
    for _ in range(len(result)):
        if result[0] in lower + upper:
            break
        result = result[1:] + result[0:1]

    return result


def hexlify(bytes):
    return hexlify_(bytes).decode('utf-8')


def encrypt(dictionary, master_key):
    """
    AES (CFB) encrypt 'dictionary' with 'master_key'.
    """
    key = hashlib.sha1(master_key.encode()).hexdigest()[:32]
    iv = os.urandom(16)
    aes_obj = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CFB, iv)
    return hexlify(iv + aes_obj.encrypt(json.dumps(dictionary, sort_keys=True)))


def decrypt(encoded, master_key):
    """
    Decrypt an AES (CFB) encrypted dictionary.
    """
    key = hashlib.sha1(master_key.encode()).hexdigest()[:32]
    iv = unhexlify(encoded[:32])
    aes_obj = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CFB, iv)
    return json.loads(aes_obj.decrypt(unhexlify(encoded[32:])))


def pbkdf2_hash(password, salt=None):
    """
    PBKDF2 HMAC-SHA-256 hash a password (100 000 iterations)
    """
    if not salt:
        salt = os.urandom(16)
    else:
        salt = unhexlify(salt)

    hash_ = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000,
        dklen=20
    )

    return hexlify(salt), hexlify(hash_)


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
        command = 'sleep {} && {} -c "import pyperclip;pyperclip.copy(\'\');"' \
                   .format(timeout, sys.executable)
        subprocess.Popen(command, stdin=subprocess.PIPE, shell=True)


class RemoteError(Exception):
    pass


class ConflictingTimestamps(RemoteError):
    pass


class UnauthorizedAccess(RemoteError):
    pass


class ServerError(RemoteError):
    pass


class File(object):

    def to_dict(self):
        d = {k: v for k, v in vars(self).items() if v}
        if 'modified' in d:
            d['modified'] = d['modified'].isoformat()
        return d

    def load(self, path):
        with open(path, 'r') as f:
            return self.loads(json.load(f))

    def loads(self, data):
        for key in data:
            if key == 'modified':
                value = dateutil.parser.parse(data[key])
            else:
                value = data[key]
            setattr(self, key, value)
        return self

    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, sort_keys=True, indent=2)

    def dumps(self, indent=None):
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)

    def encode(self):
        return base64.b64encode(self.dumps().encode()).decode('ascii')

    def decode(self, data):
        return self.loads(json.loads(base64.b64decode(data.encode()).decode('utf-8')))

    def touch(self):
        self.modified = datetime.datetime.utcnow()


class Remote(File):

    def __bool__(self):
        return bool(self.remote)

    def __nonzero__(self):
        return self.__bool__()

    def __init__(self):
        self.remote = dict()

    def initialize(self, url, token_url):
        self.remote['url'] = url
        self.remote['token_url'] = token_url

    def request(self, verb, url=None, auth=None, data=None):
        headers = {'Content-Type': 'application/json'}
        if auth is None:
            auth = requests.auth.HTTPBasicAuth(self.remote.get('token'), 'unused')
        if url is None:
            url = self.remote['url']

        response = requests.request(verb, url, headers=headers, auth=auth, data=data)

        if response.status_code == 401:
            raise UnauthorizedAccess(response.json().get('message'))
        elif response.status_code == 409:
            raise ConflictingTimestamps(response.json().get('message'))
        elif 500 > response.status_code >= 300:
            raise RemoteError(response.json())
        elif response.status_code >= 500:
            raise ServerError(response.text)

        return response.json()

    def get(self):
        data = self.request('GET')
        pts = PassTheSalt().decode(data['value'])
        modified = dateutil.parser.parse(data['modified'])
        return pts, modified

    def put(self, pts, force=False):
        payload = {'value': pts.encode()}
        if not force:
            modifieds = list()
            if hasattr(self, 'modified'):
                modifieds.append(self.modified)
            if hasattr(pts, 'modified'):
                modifieds.append(pts.modified)
            if modifieds:
                payload['modified'] = max(modifieds).isoformat()
        data = json.dumps(payload)
        self.request('PUT', data=data)

    def renew_token(self, name, password):
        auth = requests.auth.HTTPBasicAuth(name, password)
        data = self.request('GET', self.remote['token_url'], auth=auth)
        self.remote['token'] = data['token']


class PassTheSalt(File):

    def __bool__(self):
        return bool(self.config)

    def __nonzero__(self):
        return self.__bool__()

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

    def exists(self, label):
        return label in self.labels

    def get(self, label, master_password):
        master_key = self.master_key(master_password)
        info = self.labels[label]
        if info['type'] == 'generatable':
            return generate(self.generatable[label], master_key)
        elif info['type'] == 'encrypted':
            return decrypt(self.encrypted, master_key)[label]

    def _store(self, label, type):
        self.touch()
        self.labels[label] = {
            'type': type,
            'modified': datetime.date.today().strftime("%Y%m%d")
        }

    def _remove(self, label):
        self.touch()
        del self.labels[label]

    def _rename(self, label, new_label):
        self.touch()
        self.labels[new_label] = self.labels.pop(label)

    def store_generatable(self, label, salt):
        self._store(label, 'generatable')
        self.generatable[label] = salt

    def remove_generatable(self, label):
        self._remove(label)
        del self.generatable[label]

    def rename_generatable(self, label, new_label):
        self._rename(label, new_label)
        self.generatable[new_label] = self.generatable[label]

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

    def rename_encrypted(self, label, new_label, master_password):
        master_key = self.master_key(master_password)
        decrypted = decrypt(self.encrypted, master_key)
        self._rename(label, new_label)
        decrypted[new_label] = decrypted.pop(label)
        self.encrypted = encrypt(decrypted, master_key)
