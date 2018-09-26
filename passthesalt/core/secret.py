"""
Secret kinds for PassTheSalt.

This module defines various secret kinds that can be stored in a PassTheSalt
instance. A base Secret class defines all common operations for secret. A Secret
extends Schema which defines how to serialize and deserialize a secret as a
dictionary and ultimately JSON.

Generatable and Encrypted kinds extend Secret and add additional functionality.
"""

import re
from abc import ABC, abstractmethod

from passthesalt.crypto import decrypt, encrypt, generate
from passthesalt.error import ContextError, LabelError
from passthesalt.schema import Function, Parameters, Schema


class Algorithm(Schema):
    """
    Represents and defines a secret generation algorithm.
    """

    class Meta:
        constructor = Function(kwargs=Parameters(version=int, length=int))

    def __init__(self, version=1, length=None):
        """
        Create a new Algorithm.

        Args:
            version (int): the algorithm version.
            length (int): the generated length to use.
        """
        self.version = version
        self.length = length


class Secret(ABC, Schema):
    """
    Abstract class that represents and defines a secret.
    """

    kind = 'secret'

    class Meta:
        modified = True

    def to_dict(self, modified=True):
        """
        Return a dictionary representation of this Secret.

        This overrides `Schema.to_dict()` in order to insert the kind of secret.

        Args:
            modified (bool): whether to add the `modified` attribute.

        Returns:
            Dict: the dictionary representation.
        """
        d = super().to_dict(modified=modified)
        d['kind'] = self.__class__.kind
        return d

    def __getattr__(self, item):
        """
        Override the access of `_label` and `_pts` attributes.

        Raises:
            ContextError: if attributes `_label` or `_pts` are accessed outside
                of a PassTheSalt context.
        """
        if item in ('_label', '_pts'):
            raise ContextError('{} is not in a PassTheSalt context'.format(self.__class__.__name__))

        return self.__getattribute__(item)

    def display(self):
        """
        A display tuple for tabulating this secret.

        Returns:
            (Text, Text): the label and the kind.
        """
        return (self._label, self.kind.split('.')[0], self.modified)

    def add_context(self, label, pts):
        """
        Set the context for this Secret.

        Args:
            label (Text): the label for this Secret.
            pts (PassTheSalt): the PassTheSalt store for this Secret.
        """
        self._label = label
        self._pts = pts

    def remove_context(self):
        """
        Remove the context for this Secret.
        """
        del self._label
        del self._pts

    def add(self):
        """
        Add this Secret to the PassTheSalt store.
        """
        # This asserts that the Secret is in a PassTheSalt context
        self._pts
        self._label

    @abstractmethod
    def get(self):
        """
        Retrieve the secret for this Secret.

        Returns:
            Text: the secret.
        """
        raise NotImplementedError()

    def remove(self):
        """
        Remove this Secret from the PassTheSalt store.
        """
        # This asserts that the Secret is in a PassTheSalt context
        self._pts
        self._label


class Generatable(Secret):
    """
    Represents and defines a generatable Secret.
    """

    kind = 'generatable'

    class Meta:
        constructor = Function(args=Parameters(salt=str),
                               kwargs=Parameters(algorithm=Algorithm))
        modified = True

    def __init__(self, salt, algorithm=None):
        """
        Create a new Generatable.

        Args:
            salt (Text): the salt to use to generate this secret.
            algorithm (Algorithm): the algorithm to use to generate this secret.
        """
        super().__init__()

        self.salt = salt

        self.algorithm = algorithm
        if self.algorithm is None:
            self.algorithm = Algorithm()

    def display(self):
        """
        A display tuple for this tabulating this secret.

        Returns:
            (Text, Text, Text): the label, the kind, and the salt.
        """
        return super().display() + (self.salt,)

    def get(self):
        """
        Generate the secret for this Secret.

        Returns:
            Text: the secret.
        """
        return generate(
            self.salt,
            self._pts.master_key,
            version=self.algorithm.version,
            length=self.algorithm.length
        )


class Login(Generatable):
    """
    Represents and defines an account login Secret.
    """

    kind = 'generatable.login'

    class Meta:
        constructor = Function(args=Parameters(domain=str, username=str),
                               kwargs=Parameters(iteration=int, algorithm=Algorithm))
        modified = True

    def __init__(self, domain, username, iteration=None, algorithm=None):
        """
        Create a new Login.

        Args:
            domain (Text): the domain name of this login.
            username (Text): the username for this login.
            iteration (int): the secret iteration.
            algorithm (Algorithm): the algorithm to use to generate this secret.
        """
        Secret.__init__(self)

        domain = re.sub(r'[hH][tT]{2}[pP][sS]?://', '', domain).rstrip('/')
        if '.' not in domain[1:-1]:
            raise ValueError('invalid domain, must be URL')

        self.domain = domain
        self.username = username
        self.iteration = iteration

        self.algorithm = algorithm
        if self.algorithm is None:
            self.algorithm = Algorithm()

    @property
    def salt(self):
        """
        The salt for this Generatable secret.

        Returns:
            Text: the salt.
        """
        return '|'.join([self.domain, self.username, str(self.iteration or 0)])


class Encrypted(Secret):
    """
    Represents and defines an encrypted Secret.
    """

    kind = 'encrypted'

    @classmethod
    def with_secret(cls, secret):
        """
        Construct a new Encrypted Secret

        Args:
            secret (Text): the secret to encrypt.

        Returns:
            Encrypted: an Encrypted instance.
        """
        obj = Encrypted()
        obj.secret = secret
        return obj

    def _encrypt(self, secrets):
        """
        Encrypt a store with the master key.

        Args:
            secrets (Dict[Text, Text]): the store.
        """
        if not secrets:
            self._pts.secrets_encrypted = None
        else:
            self._pts.secrets_encrypted = encrypt(secrets, self._pts.master_key)

    def _decrypt(self):
        """
        Decrypt the encrypted store with the master key.

        Returns:
            Dict[Text, Text]: the encrypted store.
        """
        if not self._pts.secrets_encrypted:
            return {}

        return decrypt(self._pts.secrets_encrypted, self._pts.master_key)

    def add(self):
        """
        Add this Secret to the PassTheSalt store.
        """
        secrets = self._decrypt()
        secrets[self._label] = self.secret
        del self.secret
        self._encrypt(secrets)
        super().add()

    def get(self):
        """
        Decrypt secret for this Secret.

        Returns:
            Text: the decrypted secret.
        """
        try:
            return self._decrypt()[self._label]
        except KeyError:
            raise LabelError('"{}" does not exist in encrypted store'.format(self._label))

    def remove(self):
        """
        Remove this Secret from the PassTheSalt store.
        """
        secrets = self._decrypt()
        del secrets[self._label]
        self._encrypt(secrets)
        super().remove()
