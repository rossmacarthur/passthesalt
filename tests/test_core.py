import string

from pytest import raises

from passthesalt.core import Config, Encrypted, Generatable, Login, Master, PassTheSalt, Secret
from passthesalt.error import ConfigurationError, ContextError, LabelError, SchemaError


class TestMaster:

    def test_load(self):
        assert Master.from_dict({}) == Master()

        obj = Master.from_dict({'hash': 'thehash', 'salt': 'thesalt'})
        assert obj.hash == 'thehash'
        assert obj.salt == 'thesalt'

    def test_with_validation(self):
        obj = Master.with_validation('password')

        def is_hexstring(s):
            return isinstance(s, str) and len(s) == 40 and all(h in string.hexdigits for h in s)

        assert is_hexstring(obj.hash)
        assert is_hexstring(obj.salt)

    def test_validate(self):
        obj = Master()
        assert obj.validate('password')

        obj = Master.with_validation('password')
        assert obj.validate('password')


class TestConfig:

    def test_load(self):
        assert Config.from_dict({}) == Config()

        config = Config.from_dict({'owner': 'John Smith'})
        assert config.owner == 'John Smith'

        m = {'hash': 'thehash', 'salt': 'thesalt'}
        d = {'owner': 'John Smith', 'master': m.copy()}
        master = Master.from_dict(m)
        config = Config.from_dict(d)
        assert config.master == master
        assert config.owner == 'John Smith'
        assert config.master.to_dict() == {'hash': 'thehash', 'salt': 'thesalt'}
        assert config.to_dict() == {'owner': 'John Smith', 'master': {'hash': 'thehash',
                                                                      'salt': 'thesalt'}}


class TestSecret:
    cls = Secret

    def test___init__(self):
        with raises(TypeError):
            self.cls()

    def test_display(self):
        self.cls.__abstractmethods__ = set()

        pts = PassTheSalt()
        secret = self.cls()

        secret.add_context('test', pts)
        assert secret.display() == ('test', 'secret', secret.modified)

    def test_get(self):
        self.cls.__abstractmethods__ = set()

        secret = self.cls()

        with raises(NotImplementedError):
            secret.get()


class TestGeneratable:
    cls = Generatable

    def test_to_dict(self):
        secret = self.cls('salt')
        assert secret.to_dict(modified=False) == {'kind': 'generatable', 'salt': 'salt',
                                                  'algorithm': {'version': 1}}

    def test___getattr__(self):
        secret = self.cls('salt')

        with raises(ContextError):
            secret._pts

        with raises(ContextError):
            secret._label

        with raises(AttributeError):
            secret._derp

    def test_kind(self):
        secret = self.cls('salt')
        assert secret.kind == 'generatable'

    def test_display(self):
        pts = PassTheSalt()
        secret = self.cls('salt')

        secret.add_context('test', pts)
        assert secret.display() == ('test', 'generatable', secret.modified, 'salt')

    def test_add_context(self):
        pts = PassTheSalt()
        secret = self.cls('salt')

        secret.add_context('test', pts)
        assert secret._pts == pts
        assert secret._label == 'test'

    def test_remove_context(self):
        pts = PassTheSalt()
        secret = self.cls('salt')

        secret.add_context('test', pts)
        assert secret._pts == pts
        assert secret._label == 'test'

        secret.remove_context()
        with raises(ContextError):
            secret._pts
        with raises(ContextError):
            secret._label

    def test_add(self):
        pts = PassTheSalt()
        secret = self.cls('salt')

        with raises(ContextError):
            secret.add()

        secret.add_context('test', pts)
        secret.add()

    def test_get(self):
        pts = PassTheSalt()
        secret = self.cls('salt')

        with raises(ContextError):
            secret.get()

        secret.add_context('test', pts)
        with raises(ConfigurationError):
            secret.get()

        pts.with_master('password')
        assert secret.get() == 'M%J+hUIcYqe=LSDtSq0d'

    def test_remove(self):
        pts = PassTheSalt()
        secret = self.cls('salt')

        with raises(ContextError):
            secret.remove()

        secret.add_context('test', pts)
        secret.remove()

    def test_load(self):
        d = {'salt': 'salt'}
        secret = self.cls.from_dict(d)
        assert d == {}
        assert isinstance(secret, self.cls)


class TestLogin:
    cls = Login

    def test_to_dict(self):
        secret = self.cls('github.com', 'johnsmith')
        assert secret.to_dict(modified=False) == {'kind': 'generatable.login',
                                                  'domain': 'github.com',
                                                  'username': 'johnsmith',
                                                  'algorithm': {'version': 1}}

    def test___init__(self):
        with raises(ValueError):
            self.cls('derp', 'johnsmith')

    def test___getattr__(self):
        secret = self.cls('github.com', 'johnsmith')

        with raises(ContextError):
            secret._pts

        with raises(ContextError):
            secret._label

        with raises(AttributeError):
            secret._derp

    def test_kind(self):
        secret = self.cls('github.com', 'johnsmith')
        assert secret.kind == 'generatable.login'

    def test_display(self):
        pts = PassTheSalt()
        secret = self.cls('github.com', 'johnsmith')

        secret.add_context('test', pts)
        assert secret.display() == ('test', 'generatable', secret.modified,
                                    'github.com|johnsmith|0')

    def test_add_context(self):
        pts = PassTheSalt()
        secret = self.cls('github.com', 'johnsmith')

        secret.add_context('test', pts)
        assert secret._pts == pts
        assert secret._label == 'test'

    def test_remove_context(self):
        pts = PassTheSalt()
        secret = self.cls('github.com', 'johnsmith')

        secret.add_context('test', pts)
        assert secret._pts == pts
        assert secret._label == 'test'

        secret.remove_context()
        with raises(ContextError):
            secret._pts
        with raises(ContextError):
            secret._label

    def test_add(self):
        pts = PassTheSalt()
        secret = self.cls('github.com', 'johnsmith')

        with raises(ContextError):
            secret.add()

        secret.add_context('test', pts)
        secret.add()

    def test_get(self):
        pts = PassTheSalt()
        secret = self.cls('github.com', 'johnsmith')

        with raises(ContextError):
            secret.get()

        secret.add_context('test', pts)
        with raises(ConfigurationError):
            secret.get()

        pts.with_master('password')
        assert secret.get() == 'x3=NJJP=wfoeyzy9E2c*'

    def test_remove(self):
        pts = PassTheSalt()
        secret = self.cls('github.com', 'johnsmith')

        with raises(ContextError):
            secret.remove()

        secret.add_context('test', pts)
        secret.remove()

    def test_load(self):
        d = {'domain': 'github.com', 'username': 'johnsmith', 'iteration': 0}
        secret = self.cls.from_dict(d)
        assert d == {}
        assert isinstance(secret, self.cls)


class TestEncrypted:
    cls = Encrypted

    def test__encrypt(self):
        pts = PassTheSalt().with_master('password')
        secret = self.cls.with_secret('verysecret')

        with raises(ContextError):
            secret._encrypt({})

        secret.add_context('test', pts)
        secret._encrypt({})
        assert pts.secrets_encrypted is None

        secret._encrypt({'test': 'verysecret'})
        assert pts.secrets_encrypted is not None

    def test_kind(self):
        secret = self.cls()
        assert secret.kind == 'encrypted'

    def test__decrypt(self):
        pts = PassTheSalt().with_master('password')
        secret = self.cls.with_secret('verysecret')

        with raises(ContextError):
            secret._decrypt()

        secret.add_context('test', pts)
        assert secret._decrypt() == {}

        secret._encrypt({'test': 'verysecret'})
        assert secret._decrypt() == {'test': 'verysecret'}

    def test_add(self):
        pts = PassTheSalt().with_master('password')
        secret = self.cls.with_secret('verysecret')

        with raises(ContextError):
            secret.add()

        secret.add_context('test', pts)
        secret.add()

    def test_get(self):
        pts = PassTheSalt().with_master('password')
        secret = self.cls.with_secret('verysecret')

        with raises(ContextError):
            secret.get()

        secret.add_context('test', pts)
        with raises(LabelError):
            secret.get()

        secret.add()
        assert secret.get() == 'verysecret'

    def test_remove(self):
        pts = PassTheSalt().with_master('password')
        secret = self.cls.with_secret('verysecret')

        with raises(ContextError):
            secret.remove()

        secret.add_context('test', pts)
        secret.add()
        secret.remove()

    def test_load(self):
        d = {}
        secret = self.cls.from_dict(d)
        assert d == {}
        assert isinstance(secret, self.cls)


class TestPassTheSalt:

    def test_from_dict(self):
        # from blank dictionary
        assert PassTheSalt.from_dict({}) == PassTheSalt()
        assert PassTheSalt().to_dict(modified=False) == {}

        # from subdictionary with no secrets
        assert PassTheSalt.from_dict({'secrets': {}}) == PassTheSalt()

        # a bad dictionary
        d = {'secrets': {'test': {'salt': 'salt'}}}
        with raises(SchemaError):
            PassTheSalt.from_dict(d)

        d = {'secrets': {'test': {'salt': 'salt', 'kind': 'aroseno'}}}
        with raises(SchemaError):
            PassTheSalt.from_dict(d)

        # from dictionary with 1 secret
        d = {'secrets': {'test': {'salt': 'salt', 'kind': 'generatable'}}}
        pts0 = PassTheSalt.from_dict(d)
        assert d == {}
        pts1 = PassTheSalt()
        pts1.add('test', Generatable('salt'))
        assert pts0.to_dict(modified=False) == pts1.to_dict(modified=False)
        assert pts0 == pts1

    def test___init__(self):
        pts = PassTheSalt()
        assert pts.config == Config()
        assert pts.secrets == dict()
        assert pts.secrets_encrypted is None

    def test_with_master(self):
        pts = PassTheSalt().with_master('password')
        assert pts.master_key == 'password'

        def get_password(pts):
            nonlocal call_count
            call_count += 1
            return 'password'

        call_count = 0
        pts = PassTheSalt().with_master(get_password)
        assert pts.master_key == 'password'
        assert pts.master_key == 'password'
        assert pts.master_key == 'password'
        assert call_count == 1

    def test_resolve(self):
        pts = PassTheSalt()
        pts.add('test', Generatable('salt'))

        # if the label doesn't exist it should raise a LabelError
        with raises(LabelError):
            pts.resolve('derp')

        # if you pass in a bad regex it should raise a LabelError
        with raises(LabelError):
            pts.resolve('(')

        # all regex matches should return 'test' because it is the only label
        # matching these things
        for t in ('t', 'te', 'tes', 'test', '^test$', '[ets]{4}'):
            assert pts.resolve(pattern=t) == 'test'
        for t in ('t', 'te', 'tes', 'test'):
            assert pts.resolve(prefix=t) == 'test'

        pts.add('test2', Generatable('salt'))

        # all these regex matches match multiple things so should raise a
        # LabelError
        for t in ('t', 'te', 'tes', '[ets]{4}'):
            with raises(LabelError):
                pts.resolve(pattern=t)
        for t in ('t', 'te', 'tes'):
            with raises(LabelError):
                pts.resolve(prefix=t)

        # these match only one label exactly so that should return 'test'
        for t in ('test', '^test$'):
            assert pts.resolve(pattern=t) == 'test'
        assert pts.resolve(prefix='test') == 'test'

    def test_exists(self):
        pts = PassTheSalt()
        pts.add('test', Generatable('salt'))

        assert pts.exists(pattern='^test$')
        assert pts.exists(prefix='t')
        assert not pts.exists(pattern='^tes$')
        assert not pts.exists(prefix='e')

    def test___iter__(self):
        pts = PassTheSalt()
        pts.add('test', Generatable('salt'))

        assert list(pts.__iter__()) == list(pts.secrets.keys())

        for label in pts:
            assert label == 'test'

    def test___contains__(self):
        pts = PassTheSalt()

        pts.add('test', Generatable('salt'))
        assert 'test' in pts

        pts.remove('test')
        assert 'test' not in pts

    def test___setitem__(self):
        pts = PassTheSalt()

        secret = Generatable('salt')
        pts['test'] = secret
        assert pts.secrets['test'] == secret
        assert secret._pts == pts
        assert secret._label == 'test'

        with raises(LabelError):
            pts['test'] = Generatable('salt')

    def test___getitem__(self):
        pts = PassTheSalt()
        secret = Generatable('salt')
        pts['test'] = secret
        assert pts['test'] == secret
        assert pts['^test$'] == secret

    def test___popitem__(self):
        pts = PassTheSalt()
        secret = Generatable('salt')
        pts['test'] = secret
        assert pts.__popitem__('test') == secret
        assert 'test' not in pts

    def test___delitem__(self):
        pts = PassTheSalt()
        secret = Generatable('salt')
        pts['test'] = secret
        del pts['test']
        assert 'test' not in pts

    def test_master_key(self):
        pts = PassTheSalt()

        with raises(ConfigurationError):
            pts.master_key

        pts.with_master('password')
        assert pts.master_key == 'password'

        pts.config.owner = 'John Smith'
        assert pts.master_key == 'John Smith|password'

    def test_labels_with_prefix(self):
        pts = PassTheSalt()

        pts.add('derp', Generatable('salt'))
        assert pts.labels(prefix='tes') == []

        pts.add('test', Generatable('salt'))
        assert pts.labels(prefix='tes') == ['test']

        pts.add('test2', Generatable('salt'))
        assert sorted(pts.labels(prefix='tes')) == sorted(['test', 'test2'])

    def test_labels_matching_regex(self):
        pts = PassTheSalt()

        pts.add('derp', Generatable('salt'))
        pts.add('test', Generatable('salt'))
        assert pts.labels(pattern='^[ets]{4}$') == ['test']

        pts.add('test2', Generatable('salt'))
        assert sorted(pts.labels(pattern='^[ets]{4}2?$')) == sorted(['test', 'test2'])

    def test_add(self):
        pts = PassTheSalt()

        secret = Generatable('salt')
        pts.add('test', secret)
        assert pts.secrets['test'] == secret
        assert secret._pts == pts
        assert secret._label == 'test'

        with raises(LabelError):
            pts.add('test', Generatable('salt'))

    def test_get(self):
        pts = PassTheSalt()
        secret = Generatable('salt')
        pts.add('test', secret)
        assert pts.get('test') == secret
        assert pts.get('^test$') == secret

    def test_pop(self):
        pts = PassTheSalt()
        secret = Generatable('salt')
        pts.add('test', secret)
        assert pts.pop('test') == secret
        assert 'test' not in pts

    def test_remove(self):
        pts = PassTheSalt()
        secret = Generatable('salt')
        pts.add('test', secret)
        pts.remove('test')
        assert 'test' not in pts

    def test_relabel(self):
        pts = PassTheSalt()
        secret = Generatable('salt')
        pts.add('test', secret)
        pts.relabel('test', 'derp')
        assert 'test' not in pts
        assert 'derp' in pts

        pts.add('test2', secret)
        with raises(LabelError):
            pts.relabel('test', 'test2')
