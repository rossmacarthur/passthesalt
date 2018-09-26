import os
import tempfile
import time
from datetime import datetime, timedelta
from io import StringIO

from pytest import raises

from passthesalt.error import SchemaError
from passthesalt.schema import Function, Parameters, Schema


class TestParameters:

    def test_empty(self):
        params = Parameters()

        # no params
        d = {}
        assert params.process(d) == {}
        assert d == {}

        # unknown params
        d = {'a': 'derp'}
        assert params.process(d) == {}
        assert d == {'a': 'derp'}

    def test_plain(self):
        params = Parameters(a=str, b=int, s=Schema, d=datetime)

        # no params
        d = {}
        assert params.process(d) == {}
        assert d == {}

        # one value
        d = {'a': 'derp'}
        assert params.process(d) == {'a': 'derp'}
        assert d == {}

        d = {'a': 'derp'}
        with raises(SchemaError):
            params.process(d, validate_presence=True)

        # all params
        d = {'a': 'derp', 'b': 5}
        assert params.process(d) == {'a': 'derp', 'b': 5}
        assert d == {}

        # all and unknown params
        d = {'a': 'derp', 'b': 5, 'c': 0.0}
        assert params.process(d) == {'a': 'derp', 'b': 5}
        assert d == {'c': 0.0}

        # containing a sub Schema
        d = {'a': 'derp', 'b': 5, 's': {}}
        assert params.process(d) == {'a': 'derp', 'b': 5, 's': Schema()}
        assert d == {}

        # bad value
        d = {'a': 1}
        with raises(SchemaError):
            params.process(d)

        # containing a datetime
        d = {'d': '2018-06-19 00:00:00'}
        assert params.process(d) == {'d': datetime(year=2018, month=6, day=19)}
        assert d == {}

        # containing a bad datetime
        d = {'d': '2018-06-19aoien'}
        with raises(SchemaError):
            params.process(d)


class TestFunction:

    def test_empty(self):
        function = Function()

        # no params
        d = {}
        assert function.process(d) == ((), {})
        assert d == {}

        # unknown params
        d = {'a': 'derp'}
        assert function.process(d) == ((), {})
        assert d == {'a': 'derp'}

    def test_only_args(self):
        function = Function(args=Parameters(('a', str), ('b', int)))

        # one value
        d = {'a': 'derp'}
        with raises(SchemaError):
            function.process(d)

        # all params
        d = {'a': 'derp', 'b': 5}
        assert function.process(d) == (('derp', 5), {})
        assert d == {}

        # all and unknown params
        d = {'a': 'derp', 'b': 5, 'c': 0.0}
        assert function.process(d) == (('derp', 5), {})
        assert d == {'c': 0.0}

        # bad value
        d = {'a': 1}
        with raises(SchemaError):
            function.process(d)

    def test_only_kwargs(self):
        function = Function(kwargs=Parameters(a=str, b=int))

        # one value
        d = {'a': 'derp'}
        assert function.process(d) == ((), {'a': 'derp'})
        assert d == {}

        # all params
        d = {'a': 'derp', 'b': 5}
        assert function.process(d) == ((), {'a': 'derp', 'b': 5})
        assert d == {}

        # all and unknown params
        d = {'a': 'derp', 'b': 5, 'c': 0.0}
        assert function.process(d) == ((), {'a': 'derp', 'b': 5})
        assert d == {'c': 0.0}

        # bad value
        d = {'a': 1}
        with raises(SchemaError):
            function.process(d)

    def test_full(self):
        function = Function(args=Parameters(('a', str), ('b', int)),
                            kwargs=Parameters(c=str, d=int))

        # some params
        d = {'a': 'derp', 'd': 5}
        with raises(SchemaError):
            function.process(d)

        # all params
        d = {'a': 'derp', 'b': 5, 'c': 'derp', 'd': 5}
        assert function.process(d) == (('derp', 5), {'c': 'derp', 'd': 5})
        assert d == {}

        # all and unknown params
        d = {'a': 'derp', 'b': 5, 'c': 'derp', 'd': 5, 'e': 0.0}
        assert function.process(d) == (('derp', 5), {'c': 'derp', 'd': 5})
        assert d == {'e': 0.0}

        # bad value
        d = {'a': 1}
        with raises(SchemaError):
            function.process(d)


class TestSchema:

    def test_meta(self):

        class Example(Schema):
            class Meta:
                bad_attribute = 'naughty'

        with raises(SchemaError):
            Example.meta()

        class Example(Schema):
            class Meta:
                modified = True

        obj = Example()
        assert isinstance(obj.modified, datetime)

        old_modified = obj.modified
        time.sleep(1)
        obj.touch()
        assert obj.modified - old_modified >= timedelta(seconds=1)

    def test___bool__(self):
        obj = Schema()
        assert bool(obj) is False

        obj.a = 'derp'
        assert bool(obj) is True

    def test_from_dict(self):

        # a basic class with default Meta
        class Example(Schema):
            pass

        d = {}
        assert Example.from_dict(d) == Example()
        assert d == {}

        d = {'a': 'derp'}
        with raises(SchemaError):
            Example.from_dict(d)

        # a class with a different init
        class Example(Schema):
            class Meta:
                constructor = Function(name='create')

            @classmethod
            def create(cls):
                return cls()

        d = {}
        assert Example.from_dict(d) == Example()
        assert d == {}

        d = {'a': 'derp'}
        with raises(SchemaError):
            Example.from_dict(d)

        # a class with a different init with args
        class Example(Schema):
            class Meta:
                constructor = Function(name='create', args=Parameters(a=str))

            @classmethod
            def create(cls, a):
                return cls()

        d = {'a': 'derp'}
        assert Example.from_dict(d) == Example()
        assert d == {}

        # a class with a different init with args and kwargs
        class Example(Schema):
            class Meta:
                constructor = Function(name='create',
                                       args=Parameters(a=str), kwargs=Parameters(b=int))

            @classmethod
            def create(cls, a, b=None):
                obj = cls()
                obj.a = a
                obj.b = b
                return obj

        d = {'a': 'derp', 'b': 5}
        obj = Example.from_dict(d)
        assert obj.a == 'derp'
        assert obj.b == 5
        assert d == {}

        # a class with extra attributes
        class Example(Schema):
            class Meta:
                attributes = Parameters(a=str, b=int)

        d = {'a': 'derp', 'b': 5}
        obj = Example.from_dict(d)
        assert obj.a == 'derp'
        assert obj.b == 5
        assert d == {}

    def test_loads(self):

        # a class with extra attributes
        class Example(Schema):
            class Meta:
                attributes = Parameters(a=str)

        obj = Example.loads('{"a": "derp"}')
        assert obj.a == 'derp'

    def test_load(self):

        class Example(Schema):
            class Meta:
                attributes = Parameters(a=str)

        f = StringIO('{"a": "derp"}')
        obj = Example.load(f)
        assert obj.a == 'derp'

    def test_read(self):

        class Example(Schema):
            class Meta:
                attributes = Parameters(a=str)

        directory = tempfile.mkdtemp()
        path = os.path.join(directory, 'test')

        with open(path, 'w') as f:
            f.write('{"a": "derp"}')

        obj = Example.read(path)
        assert obj.a == 'derp'

    def test_to_dict(self):

        class Example(Schema):
            class Meta:
                datetime_format = '%Y-%m-%d'

        obj = Example()
        assert obj.to_dict() == {}

        obj.a = 'derp'
        obj.b = 5
        obj._c = 'test'
        obj.d = datetime(year=2001, month=9, day=11)
        assert obj.to_dict() == {'a': 'derp', 'b': 5, 'd': '2001-09-11'}

        sub_obj = Example()
        sub_obj.a = 'herp'
        sub_obj.b = 0.0
        obj.d = {'x': sub_obj, 'y': 100}
        assert obj.to_dict() == {'a': 'derp', 'b': 5, 'd': {'x': {'a': 'herp', 'b': 0.0}, 'y': 100}}

        obj.d = [sub_obj, 5]
        assert obj.to_dict() == {'a': 'derp', 'b': 5, 'd': [{'a': 'herp', 'b': 0.0}, 5]}

    def test_dumps(self):
        obj = Schema()
        obj.a = 'derp'
        obj.b = 5

        assert obj.dumps(sort_keys=True) == '{"a": "derp", "b": 5}'

    def test_dump(self):
        obj = Schema()
        obj.a = 'derp'
        obj.b = 5

        f = StringIO()
        obj.dump(f, sort_keys=True)

        assert f.getvalue() == '{"a": "derp", "b": 5}'

    def test_save(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, 'test')

        obj = Schema()
        obj.a = 'derp'
        obj.b = 5
        obj.save(path, sort_keys=True)

        with open(path, 'r') as f:
            assert f.read() == '{"a": "derp", "b": 5}'
