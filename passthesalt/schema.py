"""
Define a class schema for serializing and deserializing a class as JSON.
"""

import json
from collections import OrderedDict
from datetime import datetime

from passthesalt.error import SchemaError


VALID_DATETIME_FORMATS = ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f']


def parse_datetime(s):
    """
    Parse a datetime from a string.

    Args:
        s (Text): the datetime string.

    Raises:
        ValueError: when the time does not match any valid datetime formats.
    """
    for datetime_format in VALID_DATETIME_FORMATS:
        try:
            return datetime.strptime(s, datetime_format)
        except ValueError:
            pass

    raise ValueError('time {} does not match any valid formats'.format(s))


class Parameters:
    """
    Define a key value list of types.
    """

    def __init__(self, *args, **kwargs):
        """
        Create a new Parameters.

        Args:
            *args (List[Tuple[Text, Generic]]): ordered parameters defined.
            **kwargs (Dict[Text, Generic]): unordered parameters defined.
        """
        self.params = OrderedDict()
        self.update(*args, **kwargs)

    def update(self, *args, **kwargs):
        """
        Update the Parameters.

        Args:
            *args (List[Tuple[Text, Generic]]): ordered parameters to update.
            **kwargs (Dict[Text, Generic]): unordered parameters to update.
        """
        self.params.update(args, **kwargs)

    def process(self, d, validate_presence=False):
        """
        Process the input dictionary.

        Remove relevant values from the input dictionary and return a new
        OrderedDict with those parameters.

        Args:
            d (Dict): the input dictionary.
            validate_presence (bool): whether to raise a `SchemaError` if the
                name is not present.

        Raises:
            SchemaError: when the input dictionary has an invalid value or a
                required value is not present.

        Returns:
            OrderedDict: the processed parameters.
        """
        result = OrderedDict()

        for name, type_ in self.params.items():
            if name in d:
                sub = d.pop(name)

                if issubclass(type_, Schema) and (sub is None or isinstance(sub, dict)):
                    result[name] = type_.from_dict(sub or {})
                elif issubclass(type_, datetime) and isinstance(sub, str):
                    try:
                        result[name] = parse_datetime(sub)
                    except ValueError:
                        raise SchemaError('invalid datetime format, name={}, expected={}, actual={}'
                                          .format(name, type_, sub))
                elif isinstance(sub, type_):
                    result[name] = sub
                else:
                    raise SchemaError('invalid value, name={}, expected={}, actual={}'
                                      .format(name, type_, sub))

            elif validate_presence:
                raise SchemaError('value is required; name={}'.format(name))

        return result


class Function:
    """
    Define a function and how to call it.
    """

    def __init__(self, name=None, args=None, kwargs=None):
        """
        Create a new `Function`.

        Args:
            name (Text): the name of the function.
            args (Parameters): decription of the function arguments.
            kwargs (Parameters): decription of the function keyword arguments.
        """
        self.name = name
        self.args = args or Parameters()
        self.kwargs = kwargs or Parameters()

    def process(self, d):
        """
        Process the input dictionary.

        Remove relevant values from the input dictionary and return two
        OrderedDicts with those parameters.

        Args:
            d (Dict): the input dictionary.

        Returns:
            Tuple[Tuple, OrderedDict]: the processed args and kwargs.
        """
        args = tuple(self.args.process(d, validate_presence=True).values())
        kwargs = self.kwargs.process(d)
        return (args, kwargs)

    def __call__(self, cls, d):
        """
        Call the described function using data from the input dictionary.

        Args:
            cls (Generic): the class whose function we need to call.
            d (Dict): the input dictionary.

        Returns:
            Any: the result of the called function.
        """
        args, kwargs = self.process(d)

        if self.name is None or self.name == '__init__':
            return cls(*args, **kwargs)

        return getattr(cls, self.name)(*args, **kwargs)


class Schema:
    """
    Define how to serialize and deserialize a class as JSON.
    """

    def __init__(self):
        """
        Create a new Schema.
        """
        self.touch()

    def __bool__(self):
        """
        Return True if serializing this class would result in any data.
        """
        return bool(self.to_dict(modified=False))

    def __eq__(self, other):
        """
        Whether to Schemas are equal.

        Schemas are equal if they are the same class and their serialized
        dictionaries are the same.

        Args:
            other (Schema): the class to compare this one to.

        Returns:
            bool: True if equal else False.
        """
        return (isinstance(other, self.__class__) and
                self.to_dict(modified=False) == other.to_dict(modified=False))

    def touch(self):
        """
        Update the modified time of this object to the current UTC time.
        """
        meta = self.meta()

        if meta.modified:
            self.modified = datetime.utcnow()

    @classmethod
    def meta(cls):
        """
        Return the Meta information for this Schema.

        Returns:
            Meta: the meta class.
        """
        class Meta:
            constructor = Function()
            attributes = Parameters()
            datetime_format = '%Y-%m-%d %H:%M:%S'
            modified = False

        if hasattr(cls, 'Meta'):

            for attr, value in vars(cls.Meta).items():
                if attr.startswith('_'):
                    continue

                if attr in ('constructor', 'attributes', 'datetime_format', 'modified'):
                    setattr(Meta, attr, value)
                else:
                    raise SchemaError('unexpected Meta attribute: {}'.format(attr))

        if Meta.modified:
            Meta.attributes.update(modified=datetime)

        return Meta

    @classmethod
    def from_dict(cls, d):
        """
        Create a Schema object from a dictionary.

        Args:
            d (Dict): the input dictionary.

        Returns:
            Schema: a new Schema object.
        """
        meta = cls.meta()

        obj = meta.constructor(cls, d)

        for key, value in meta.attributes.process(d).items():
            setattr(obj, key, value)

        if d != {}:
            raise SchemaError('unknown names and values: {}'.format(d))

        return obj

    @classmethod
    def loads(cls, s, *args, **kwargs):
        """
        Create a Schema object from a string.

        Args:
            s (Text): the input string.
            *args: extra arguments passed directly to `json.loads()`
            **kwargs: extra keyword arguments passed directly to `json.loads()`.

        Returns:
            Schema: a new Schema object.
        """
        return cls.from_dict(json.loads(s, *args, **kwargs))

    @classmethod
    def load(cls, f, *args, **kwargs):
        """
        Create a Schema object from file-like object.

        Args:
            f (File): a file-like object to load from.
            *args: extra arguments passed directly to `json.load()`
            **kwargs: extra keyword arguments passed directly to `json.load()`.

        Returns:
            Schema: a new Schema object.
        """
        return cls.from_dict(json.load(f, *args, **kwargs))

    @classmethod
    def read(cls, p, *args, **kwargs):
        """
        Create a Schema object loaded from a file path.

        Args:
            p (Text): the file path to read from.
            *args: extra arguments passed directly to `json.load()`
            **kwargs: extra keyword arguments passed directly to `json.load()`.

        Returns:
            Schema: a new Schema object.
        """
        with open(p, 'r') as f:
            return cls.load(f, *args, **kwargs)

    def to_dict(self, modified=True):
        """
        Return a dictionary representation of this Schema.

        Recursively calls `to_dict()` on sub Schema objects. Datetime objects
        are serialized as per this Schemas Meta subclass.

        Args:
            modified (bool): whether to add the `modified` attribute.

        Returns:
            Dict: the dictionary representation.
        """
        def _to_dict(v):
            if isinstance(v, dict):
                result = {a: _to_dict(b) for a, b in v.items()
                          if not a.startswith('_') and (modified or a != 'modified')}
                return {a: b for a, b in result.items() if b not in (None, [], {})}
            elif isinstance(v, list):
                return [_to_dict(e) for e in v]
            elif isinstance(v, datetime):
                meta = self.meta()
                return v.strftime(meta.datetime_format)
            elif isinstance(v, Schema):
                return v.to_dict(modified=modified)
            else:
                return v

        return _to_dict(vars(self))

    def dumps(self, *args, **kwargs):
        """
        Return a string representation of this Schema.

        Args:
            *args: extra arguments passed directly to `json.dumps()`
            **kwargs: extra keyword arguments passed directly to `json.dumps()`.

        Returns:
            Text: the string representation.
        """
        return json.dumps(self.to_dict(), *args, **kwargs)

    def dump(self, f, *args, **kwargs):
        """
        Write a representation of this Schema to the given file object.

        Args:
            f (File): a file-like object to dump to.
            *args: extra arguments passed directly to `json.dump()`
            **kwargs: extra keyword arguments passed directly to `json.dump()`.
        """
        json.dump(self.to_dict(), f, *args, **kwargs)

    def save(self, p, *args, **kwargs):
        """
        Write a representation of this Schema to the given path.

        Args:
            p (Text): the file path to save to.
            *args: extra arguments passed directly to `json.dump()`
            **kwargs: extra keyword arguments passed directly to `json.dump()`.
        """
        with open(p, 'w') as f:
            self.dump(f, *args, **kwargs)
