"""
The core PassTheSalt store.

This module defines a PassTheSalt object which stores different kinds of
Secrets. A PassTheSalt extends Schema so that it can be serialized and
deserialized as a dictionary and ultimately JSON.
"""

import re
from hmac import compare_digest

from passthesalt.crypto import pbkdf2_hash
from passthesalt.error import ConfigurationError, LabelError, SchemaError
from passthesalt.schema import Parameters, Schema

from .secret import Encrypted, Generatable, Login


class Master(Schema):
    """
    Represents and defines a master password.

    Stores a hash and salt that can be used to validate a later given master
    password.
    """

    class Meta:
        attributes = Parameters(hash=str, salt=str)

    @classmethod
    def with_validation(cls, master):
        """
        Configure master validation with the given master.

        Args:
            master (Text): the master password.
        """
        obj = cls()
        obj.salt, obj.hash = pbkdf2_hash(master)
        return obj

    def validate(self, master):
        """
        Validate the given master with the stored hash.

        Args:
            master (Text): the master password.

        Returns:
            bool: whether the master matches. True if there is no configured
                validation.
        """
        if not hasattr(self, 'hash'):
            return True

        return compare_digest(self.hash, pbkdf2_hash(master, self.salt)[1])


class Config(Schema):
    """
    Represents and defines config for PassTheSalt.

    Stores the owner name and master password validation.
    """

    class Meta:
        attributes = Parameters(owner=str, master=Master)

    def __init__(self):
        """
        Create a new empty Config.
        """
        self.master = Master()


class PassTheSalt(Schema):
    """
    An object to store and manage Secrets.

    A PassTheSalt represents and defines a  deterministic password generation
    and password storage system.
    """

    class Meta:
        attributes = Parameters(config=Config, master=str, secrets=dict,
                                secrets_encrypted=str, version=str)
        modified = True

    @classmethod
    def from_dict(cls, d):
        """
        Create a PassTheSalt object from a dictionary.

        Args:
            d (Dict): the input dictionary.

        Returns:
            PassTheSalt: a new PassTheSalt object.
        """
        pts = super().from_dict(d)

        # Remove the secrets dictionary from the object, and then readd them
        # with the proper process
        secrets = pts.secrets
        pts.secrets = {}

        for label in secrets:
            kind = secrets[label].pop('kind', None)

            try:
                klass = {
                    'encrypted': Encrypted,
                    'generatable': Generatable,
                    'generatable.login': Login
                }[kind]
            except KeyError:
                raise SchemaError('invalid secret kind "{}"'.format(kind))

            secret = klass.from_dict(secrets[label])
            secret.add_context(label, pts)
            pts.secrets[label] = secret

        return pts

    def __init__(self):
        """
        Create a new empty PassTheSalt.
        """
        super().__init__()
        self.config = Config()
        self.secrets = {}
        self.secrets_encrypted = None
        self._master = None

    def with_master(self, master):
        """
        Configure PassTheSalt with a master password.

        Args:
            master: the master password for generating and encrypting secrets.
                This can be a callback for getting the password (for example
                through user input), or the actual master password as a string.
        """
        self._master = master
        return self

    def __iter__(self):
        """
        Iterate over the secrets.

        Returns:
            Iterable: an iterator over the dictionary of secrets.
        """
        return self.secrets.__iter__()

    def __contains__(self, label):
        """
        Whether the label exists.

        Return whether this PassTheSalt instance contains a secret with the
        given label.

        Args:
            label (Text): the label of the secret.

        Returns:
            bool: True if the label exists, else False.
        """
        return label in self.secrets

    def __setitem__(self, label, secret):
        """
        Add a secret.

        Args:
            label (Text): the label for the secret.
            secret (Secret): the secret to add.

        Raises:
            LabelError: when the label already exists in the store.
        """
        if label in self.secrets:
            raise LabelError('"{}" already exists'.format(label))

        secret.add_context(label, self)
        secret.add()
        self.secrets[label] = secret
        self.touch()

    def __getitem__(self, pattern):
        """
        Retrieve a secret.

        Args:
            pattern (Text): a pattern matching the label of the secret.

        Returns:
            Secret: the secret corresponding to the pattern.
        """
        return self.secrets[self.resolve(pattern=pattern)]

    def __popitem__(self, pattern):
        """
        Remove a secret and return the removed secret.

        Args:
            pattern (Text): a pattern matching the label of the secret.

        Returns:
            Secret: the secret corresponding to the pattern.
        """
        secret = self.secrets.pop(self.resolve(pattern=pattern))
        secret.remove()
        secret.remove_context()
        self.touch()
        return secret

    def __delitem__(self, pattern):
        """
        Remove a secret.

        Args:
            pattern (Text): a pattern matching the label of the secret.
        """
        self.__popitem__(pattern)

    @property
    def master_key(self):
        """
        The master key constructed from the master password and owner config.

        Returns:
            Text: the master key.
        """
        if self._master is None:
            raise ConfigurationError('master password is not configured')

        if callable(self._master):
            self._master = self._master(self)

        key = []

        if hasattr(self.config, 'owner'):
            key.append(self.config.owner)

        key.append(self._master)

        return '|'.join(key)

    def labels(self, pattern=None, prefix=None):
        """
        Return the list of labels for secrets.

        This list can be optionally filtered with a regex pattern or prefix.

        Args:
            pattern (Text): filter labels with a regex pattern.
            prefix (Text): filter labels that start with a prefix.

        Raises:
            LabelError: when the given pattern is an invalid regex expression.

        Returns:
            List[Text]: a list of labels matching the given pattern and prefix.
        """
        labels = list(self.secrets.keys())

        if prefix:
            labels = list(filter(lambda s: s.startswith(prefix), labels))

        if pattern:
            try:
                regex = re.compile(pattern)
            except re.error:
                raise LabelError('"{}" is an invalid regex expression'.format(pattern))

            labels = list(filter(lambda s: regex.match(s), labels))

        return labels

    def resolve(self, pattern=None, prefix=None):
        """
        Resolve a pattern and prefix to a single label.

        Args:
            pattern (Text): filter labels with a regex pattern.
            prefix (Text): filter labels that start with a prefix.

        Raises:
            LabelError: if the pattern or prefix does not match any labels or
                multiple labels are matched.

        Returns:
            Text: the actual label of the secret.
        """
        if pattern and pattern in self:
            return pattern

        if prefix and prefix in self:
            return prefix

        matches = self.labels(pattern=pattern, prefix=prefix)

        if len(matches) == 1:
            return matches[0]

        to_join = []
        if pattern:
            to_join.append('pattern "{}"'.format(pattern))
        if prefix:
            to_join.append('prefix "{}"'.format(prefix))
        p_and_p_text = ' and '.join(to_join)

        if not matches:
            raise LabelError('unable to resolve ' + p_and_p_text)

        raise LabelError(p_and_p_text + ' matches multiple secrets')

    def exists(self, pattern=None, prefix=None):
        """
        Whether a pattern and prefix resolve to a single label.

        Args:
            pattern (Text): filter labels with a regex pattern.
            prefix (Text): filter labels that start with a prefix.

        Returns:
            bool: True if the pattern and prefix resolve to a single label.
        """
        try:
            self.resolve(pattern=pattern, prefix=prefix)
            return True
        except LabelError:
            return False

    def add(self, label, secret):
        """
        Add a secret to PassTheSalt.

        Args:
            label (Text): the label for the secret.
            secret (Secret): the secret to add.
        """
        self[label] = secret

    def get(self, pattern):
        """
        Retrieve a secret.

        Args:
            pattern (Text): a pattern matching the label of the secret.

        Returns:
            Secret: the secret corresponding to the pattern.
        """
        return self[pattern]

    def pop(self, pattern):
        """
        Remove a secret and return the removed secret.

        Args:
            pattern (Text): a pattern matching the label of the secret.
        """
        return self.__popitem__(pattern)

    def remove(self, pattern):
        """
        Remove a secret.

        Args:
            pattern (str): a pattern matching the label of the secret.
        """
        del self[pattern]

    def relabel(self, pattern, label):
        """
        Rename a secret.

        Args:
            pattern (Text): a pattern matching the label of the secret.
            label (Text): the new label of the secret.
        """
        if label in self:
            raise LabelError('"{}" already exists'.format(label))

        self[label] = self.__popitem__(pattern)
