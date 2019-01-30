import datetime
import string
import tempfile
from unittest import mock

import serde
from pytest import raises

from passthesalt import __version__
from passthesalt.core import (
    Config, Encrypted, Generatable, Login, Master, PassTheSalt, Secret, version
)
from passthesalt.exceptions import ConfigurationError, ContextError, LabelError


class SecretSub(Secret):
    pass


def test_version():
    assert version() == __version__


@mock.patch.dict('passthesalt.core.SECRETS', {'secret': SecretSub})
@mock.patch.dict('passthesalt.core.KINDS', {SecretSub: 'secret'})
class TestSecret:

    def test_from_dict(self):
        given = {
            'kind': 'secret',
            'modified': '2017-12-29'
        }
        expected = SecretSub(
            modified=datetime.datetime(year=2017, month=12, day=29)
        )
        assert Secret.from_dict(given) == expected

    def test_from_dict_invalid_kind(self):
        with raises(serde.exceptions.DeserializationError):
            Secret.from_dict({
                'kind': 'unknown',
                'modified': '2017-12-29'
            })

    def test_to_dict(self):
        given = SecretSub(
            modified=datetime.datetime(year=2017, month=12, day=29)
        )
        expected = {
            'kind': 'secret',
            'modified': '2017-12-29'
        }
        assert given.to_dict() == expected

    def test_to_dict_unknown_kind(self):
        class SecretSub2(Secret):
            pass

        with raises(serde.exceptions.SerializationError):
            SecretSub2().to_dict()

    def test___getattr__(self):
        example = Secret()

        with raises(ContextError):
            example._pts

        with raises(ContextError):
            example._label

        with raises(AttributeError):
            example._something

    def test_display(self):
        example = SecretSub()
        example.add_context('example', object())
        assert example.display() == ('example', 'secret', example.modified)

    def test_add_context(self):
        example = SecretSub()
        label = 'example'
        pts = object()
        example.add_context(label, pts)
        assert example._label == 'example'
        assert example._pts == pts

    def test_check_context(self):
        example = SecretSub()

        with raises(ContextError):
            example.check_context()

        example.add_context('example', object())

        assert example.check_context() is None

    def test_remove_context(self):
        example = SecretSub()
        example.add_context('example', object())
        example.remove_context()

        with raises(ContextError):
            example.check_context()

    def test_get(self):
        with raises(NotImplementedError):
            Secret().get()


class TestGeneratable:

    def test_display(self):
        modified = datetime.datetime(year=2018, month=12, day=25)
        secret = Generatable(salt='test', modified=modified)
        secret._label = 'Example'
        assert secret.display() == ('Example', 'generatable', modified, 'test')

    def test_get(self):
        pts = PassTheSalt().with_master('password')
        secret = Generatable(salt='test')
        secret.add_context('Example', pts)
        assert secret.get() == 'CV*2qua!A3rwh0fwf8o*'


class TestLogin:

    def test_salt(self):
        pts = PassTheSalt().with_master('password')
        secret = Login(domain='www.test.com', username='test')
        secret.add_context('Example', pts)
        assert secret.salt == 'www.test.com|test|0'
        assert secret.get() == 'j4RETtUP7xyQcR%Lc1k+'


class TestEncrypted:

    def test___init__(self):
        secret = Encrypted('verysecure')
        assert secret.secret == 'verysecure'

    def test__encrypt_and__decrypt(self):
        pts = PassTheSalt().with_master('password')
        secret = Encrypted('verysecure')
        secret.add_context('Example', pts)
        assert pts.secrets_encrypted is None
        assert secret._decrypt() == {}
        secret._encrypt({'Example': secret.secret})
        assert secret._decrypt() == {'Example': secret.secret}

    def test_add(self):
        pts = PassTheSalt().with_master('password')
        secret = Encrypted('verysecure')
        secret.add_context('Example', pts)
        assert pts.secrets_encrypted is None
        secret.add()
        assert bool(pts.secrets_encrypted)
        assert not hasattr(secret, 'secret')

    def test_get(self):
        pts = PassTheSalt().with_master('password')
        secret = Encrypted('verysecure')
        secret.add_context('Example', pts)
        secret.add()
        assert secret.get() == 'verysecure'

    def test_get_missing(self):
        pts = PassTheSalt().with_master('password')
        secret = Encrypted('verysecure')
        secret.add_context('Example', pts)
        secret.add()
        pts.secrets_encrypted = None
        with raises(LabelError):
            secret.get()

    def test_remove(self):
        pts = PassTheSalt().with_master('password')
        secret = Encrypted('verysecure')
        secret.add_context('Example', pts)
        secret.add()
        secret.remove()
        assert pts.secrets_encrypted is None


class TestMaster:

    def test___init__(self):
        def is_hexstring(s):
            return (
                isinstance(s, str)
                and len(s) == 40
                and all(h in string.hexdigits for h in s)
            )

        example = Master('password')
        assert is_hexstring(example.hash)
        assert is_hexstring(example.salt)
        assert not hasattr(example, 'password')

    def test_is_valid(self):
        master = Master('password')
        assert master.is_valid('password') is True
        assert master.is_valid('password2') is False


class TestPassTheSalt:

    def test_from_dict_no_secrets(self):
        given = {
            'config': {
                'master': {
                    'salt': 'b32ad5ad536b2e3b790050845b65311b333e6480',
                    'hash': '300148d88175b2d9cf52001f29e716de1b3a56ea'
                },
                'owner': 'John Smith'
            },
            'modified': '2018-12-25'
        }
        expected = PassTheSalt(
            config=Config(
                owner='John Smith',
                master=Master.from_dict({
                    'salt': 'b32ad5ad536b2e3b790050845b65311b333e6480',
                    'hash': '300148d88175b2d9cf52001f29e716de1b3a56ea'
                })
            ),
            modified=datetime.datetime(year=2018, month=12, day=25)
        )
        assert PassTheSalt.from_dict(given) == expected

    def test_from_dict_secrets(self):
        given = {
            'config': {
                'master': {
                    'salt': 'b32ad5ad536b2e3b790050845b65311b333e6480',
                    'hash': '300148d88175b2d9cf52001f29e716de1b3a56ea'
                },
                'owner': 'John Smith'
            },
            'secrets': {
                'Example': {
                    'algorithm': {
                        'version': 1
                    },
                    'salt': 'test',
                    'kind': 'generatable',
                    'modified': '2018-12-25'
                }
            },
            'modified': '2018-12-25'
        }
        expected = PassTheSalt(
            config=Config(
                owner='John Smith',
                master=Master.from_dict({
                    'salt': 'b32ad5ad536b2e3b790050845b65311b333e6480',
                    'hash': '300148d88175b2d9cf52001f29e716de1b3a56ea'
                })
            )
        )
        modified = datetime.datetime(year=2018, month=12, day=25)
        expected.add('Example', Generatable(modified=modified, salt='test'))
        expected.modified = modified
        assert PassTheSalt.from_dict(given) == expected

    def test_save(self):
        with tempfile.NamedTemporaryFile() as t:
            pts = PassTheSalt().with_path(t.name)
            pts.save()
            assert PassTheSalt.from_path(t.name) == pts

    def test_with_master(self):
        pts = PassTheSalt()
        assert pts.with_master('password') is pts
        assert pts._master == 'password'

    def test_with_path(self):
        pts = PassTheSalt()
        assert pts.with_path('example') is pts
        assert pts._path == 'example'

    def test_master_key_empty(self):
        pts = PassTheSalt()
        with raises(ConfigurationError):
            pts.master_key

    def test_master_key_no_owner(self):
        pts = PassTheSalt()
        assert pts.with_master('password').master_key == 'password'

    def test_master_key_owner(self):
        pts = PassTheSalt(config=Config(owner='John Smith'))
        assert pts.with_master('password').master_key == 'John Smith|password'

    def test_master_key_callable_master(self):
        pts = PassTheSalt()
        assert pts.with_master(lambda x: 'password').master_key == 'password'

    def test_path(self):
        pts = PassTheSalt().with_path('test')
        assert pts.path == 'test'

    def test_path_empty(self):
        pts = PassTheSalt()
        with raises(ConfigurationError):
            pts.path

    def test_labels_no_pattern(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='test'))
        assert pts.labels() == ['Example']

    def test_labels_good_pattern(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='test'))
        pts.add('Example2', Generatable(salt='test'))
        pts.add('3Example', Generatable(salt='test'))
        expected = {'Example', 'Example2', '3Example'}
        assert set(pts.labels(pattern=r'\d?Example\d?')) == expected

    def test_labels_bad_pattern(self):
        pts = PassTheSalt()
        with raises(LabelError):
            pts.labels(pattern='(')

    def test_resolve_not_exists(self):
        pts = PassTheSalt()
        with raises(LabelError):
            pts.resolve(pattern='Example')

    def test_resolve_exact(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='test'))
        assert pts.resolve(pattern='Example') == 'Example'

    def test_resolve_exists(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='test'))
        assert pts.resolve(pattern='[aelmpxE]{7}') == 'Example'

    def test_resolve_multiple(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='test'))
        pts.add('Example2', Generatable(salt='test'))
        with raises(LabelError):
            pts.resolve(pattern=r'^Example\d?$')

    def test_resolve_one(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='test'))
        pts.add('Example2', Generatable(salt='test'))
        assert pts.resolve(pattern=r'^Example$') == 'Example'

    def test_contains(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='test'))
        assert pts.contains('Example') is True
        assert pts.contains('Example2') is False

    def test_add_not_exists(self):
        pts = PassTheSalt()
        secret = Generatable(salt='salt')
        with raises(ContextError):
            secret.check_context()
        pts.add('Example', secret)
        assert secret._pts is pts
        assert secret._label == 'Example'

    def test_add_exists(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='salt'))
        with raises(LabelError):
            pts.add('Example', Generatable(salt='salt'))

    def test_get(self):
        pts = PassTheSalt()
        secret = Generatable(salt='salt')
        pts.add('Example', secret)
        assert pts.get('Example') is secret

    def test_pop(self):
        pts = PassTheSalt()
        secret = Generatable(salt='salt')
        pts.add('Example', secret)
        assert pts.pop('Example') is secret
        assert not pts.contains('Example')
        with raises(ContextError):
            secret._pts

    def test_pop_not_exists(self):
        pts = PassTheSalt()
        with raises(LabelError):
            pts.pop('Example')

    def test_remove(self):
        pts = PassTheSalt()
        secret = Generatable(salt='salt')
        pts.add('Example', secret)
        assert pts.contains('Example')
        pts.remove('Example')
        assert not pts.contains('Example')
        with raises(ContextError):
            secret._pts
        with raises(ContextError):
            secret._label

    def test_move(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='salt'))
        assert pts.contains('Example')
        assert not pts.contains('Example2')
        pts.move('Example', 'Example2')
        assert not pts.contains('Example')
        assert pts.contains('Example2')

    def test_move_already_exists(self):
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='salt'))
        with raises(LabelError):
            pts.move('test', 'Example')

    def test__diff(self):
        pts = PassTheSalt()
        other = PassTheSalt()
        secret = Generatable(salt='salt')
        pts.add('Example', secret)
        diff = pts._diff(other)
        assert diff.get('Example') == secret
        assert not other._diff(pts).labels()
