"""
Extensions for serde for use in PassTheSalt.
"""

import datetime
from base64 import b64decode, b64encode

from serde import Model, fields


class DateTime(fields.DateTime):
    """
    A custom DateTime Field that uses multiple valid formats.
    """

    formats = ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d')

    def __init__(self, **kwargs):
        """
        Create a new DateTime.

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
        Deserialize the given string as a `~datetime.datetime`.

        Deserializes using one of the valid formats.

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


class ModifiedModel(Model):
    """
    A custom Model that has a modified Field.
    """

    modified = fields.Optional(DateTime, default=datetime.datetime.utcnow)

    @classmethod
    def from_base64(cls, s, strict=True, **kwargs):
        """
        Create a PassTheSalt from a base64 encoded string.

        Args:
            s (str): the base64 encoded input string.
            strict (bool): if set to False then no exception will be raised when
                unknown dictionary keys are present.
            **kwargs: extra keyword arguments passed directly to `json.loads()`.

        Returns:
            PassTheSalt: a new PassTheSalt instance.
        """
        return cls.from_json(b64decode(s.encode()).decode('utf-8'), strict=strict, **kwargs)

    @classmethod
    def from_path(cls, p, strict=True, **kwargs):
        """
        Create a PassTheSalt from the given file path.

        Args:
            p (str): the file path to read from.
            strict (bool): if set to False then no exception will be raised when
                unknown dictionary keys are present.
            **kwargs: extra keyword arguments passed directly to `json.loads()`.

        Returns:
            PassTheSalt: a new PassTheSalt instance.
        """
        with open(p) as f:
            return cls.from_json(f.read(), strict=strict, **kwargs)

    def to_base64(self, dict=None, **kwargs):
        """
        Base64 encode a JSON dumped representation of this PassTheSalt.

        Args:
            dict (type): the class of the deserialized dictionary. This defaults
                to an `OrderedDict` so that the fields will be returned in the
                order they were defined on the Model.
            **kwargs: extra keyword arguments passed directly to `json.dumps()`.

        Returns:
            str: the base64 encoded representation of the PassTheSalt store.
        """
        return b64encode(self.to_json(dict=dict, **kwargs).encode()).decode('ascii')

    def to_path(self, p, dict=None, **kwargs):
        """
        Write this PassTheSalt store to the given path.

        Args:
            p (str): the file path to write to
            dict (type): the class of the deserialized dictionary. This defaults
                to an `OrderedDict` so that the fields will be returned in the
                order they were defined on the Model.
            **kwargs: extra keyword arguments passed directly to `json.dumps()`.
        """
        with open(p, 'w') as f:
            f.write(self.to_json(dict=dict, **kwargs))

    def touch(self):
        """
        Update the modified time of this object to the current UTC time.
        """
        self.modified = datetime.datetime.utcnow()
