"""
Extensions for serde for use in PassTheSalt.
"""

import datetime
from base64 import b64decode, b64encode

import toml
from serde import Model as BaseModel
from serde import fields


class DateTime(fields.DateTime):
    """
    A custom `DateTime` `Field` that uses multiple valid formats.
    """

    formats = ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d')

    def __init__(self, **kwargs):
        """
        Create a new `DateTime`.

        Args:
            **kwargs: keyword arguments for the `Field` constructor.
        """
        super().__init__(**kwargs)
        del self.format

    def serialize(self, value):
        """
        Serialize the given `~datetime.datetime` as a string.

        Args:
            value (~datetime.datetime): the datetime object to serialize.

        Returns:
            str: a string representation of the datetime.
        """
        if value.microsecond:
            format = self.formats[0]
        elif value.hour or value.minute or value.second:
            format = self.formats[1]
        else:
            format = self.formats[2]

        return value.strftime(format)

    def deserialize(self, value):
        """
        Deserialize the given string as a `~datetime.datetime` using one of the
        valid formats.

        Args:
            value (str): the string to deserialize.

        Returns:
            ~datetime.datetime: the deserialized datetime.
        """
        for datetime_format in self.formats:
            try:
                return datetime.datetime.strptime(value, datetime_format)
            except ValueError:
                pass

        raise ValueError(f'datetime {value!r} does not match any valid formats')


class Model(BaseModel):
    """
    A custom Model that has a modified Field.
    """

    modified: fields.Optional(DateTime, default=datetime.datetime.utcnow)

    def to_base64(self, **kwargs):
        """
        Dump the model as a JSON string and base64 encode it.

        Args:
            **kwargs: extra keyword arguments to pass directly to `json.dumps`.

        Returns:
            str: a base64 encoded representation of this model.
        """
        return b64encode(self.to_json(**kwargs).encode()).decode('ascii')

    def to_toml(self, **kwargs):
        """
        Dump the model as a TOML string.

        Args:
            **kwargs: extra keyword arguments to pass directly to `toml.dumps`.

        Returns:
            str: a TOML representation of this model.
        """
        return toml.dumps(self.to_dict(), **kwargs)

    def to_path(self, p, dict=None, **kwargs):
        """
        Dump the model to a file path.

        Args:
            p (str): the file path to write to.
            **kwargs: extra keyword arguments to pass directly to `json.dumps`.
        """
        with open(p, 'w') as f:
            f.write(self.to_json(**kwargs))

    @classmethod
    def from_base64(cls, s, **kwargs):
        """
        Load the model from a base64 encoded string.

        Args:
            s (str): the JSON string.
            **kwargs: extra keyword arguments to pass directly to `json.loads`.

        Returns:
            Model: an instance of this model.            .
        """
        return cls.from_json(b64decode(s.encode()).decode('utf-8'), **kwargs)

    @classmethod
    def from_toml(cls, s, **kwargs):
        """
        Load the model from a TOML string.

        Args:
            s (str): the TOML string.
            **kwargs: extra keyword arguments to pass directly to `toml.loads`.

        Returns:
            Model: an instance of this model.
        """
        return cls.from_dict(toml.loads(s, **kwargs))

    @classmethod
    def from_path(cls, p, **kwargs):
        """
        Load the model from a file path.

        Args:
            p (str): the file path to read from.
            **kwargs: extra keyword arguments to pass directly to `json.loads`.

        Returns:
            Model: an instance of this model.            .
        """
        with open(p) as f:
            return cls.from_json(f.read(), **kwargs)

    def touch(self):
        """
        Update the modified time of this object to the current UTC time.
        """
        self.modified = datetime.datetime.utcnow()
