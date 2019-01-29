import datetime
import tempfile

from pytest import raises

from passthesalt.model import DateTime, ModifiedModel


class TestDateTime:

    def test___init__(self):
        example = DateTime(validators=[])
        assert example.validators == []
        assert not hasattr(example, 'format')

    def test_serialize(self):
        value = datetime.datetime(year=2017, month=12, day=29)
        assert DateTime().serialize(value) == '2017-12-29'

        value = datetime.datetime(year=2017, month=12, day=29, hour=10)
        assert DateTime().serialize(value) == '2017-12-29 10:00:00'

        value = datetime.datetime(year=2017, month=12, day=29, microsecond=1000)
        assert DateTime().serialize(value) == '2017-12-29 00:00:00.001000'

    def test_deserialize(self):
        expected = datetime.datetime(year=2017, month=12, day=29)
        assert DateTime().deserialize('2017-12-29') == expected
        assert DateTime().deserialize('2017-12-29 00:00:00') == expected
        assert DateTime().deserialize('2017-12-29 00:00:00.000000') == expected

    def test_deserialize_invalid(self):
        with raises(ValueError):
            DateTime().deserialize('2017-12-29T00:00:00')


class TestModifiedModel:

    def test_from_base64(self):
        value = 'eyJtb2RpZmllZCI6ICIyMDE4LTEyLTI1IDAwOjAwOjAwIn0='
        expected = ModifiedModel(
            modified=datetime.datetime(year=2018, month=12, day=25)
        )
        assert ModifiedModel.from_base64(value) == expected

    def test_from_path(self):
        example = ModifiedModel(
            modified=datetime.datetime(year=2018, month=12, day=25)
        )
        with tempfile.NamedTemporaryFile() as t:
            with open(t.name, 'w') as f:
                f.write(example.to_json())
            assert ModifiedModel.from_path(t.name) == example

    def test_to_base64(self):
        example = ModifiedModel(
            modified=datetime.datetime(year=2018, month=12, day=25)
        )
        expected = 'eyJtb2RpZmllZCI6ICIyMDE4LTEyLTI1In0='
        assert example.to_base64() == expected

    def test_to_path(self):
        example = ModifiedModel()
        with tempfile.NamedTemporaryFile() as t:
            example.to_path(t.name, sort_keys=True)
            with open(t.name) as f:
                assert f.read() == example.to_json(sort_keys=True)
