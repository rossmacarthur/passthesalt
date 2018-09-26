from click.testing import CliRunner

from passthesalt.cli import cli
from passthesalt.core import Encrypted, Generatable, Master, PassTheSalt


class TestCli:

    def test_cli(self):
        runner = CliRunner()

        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ['--path', 'passthesalt'],
                input='John Smith\ny\npassword\npassword\n'
            )
            assert result.exit_code == 0
            assert 'Initializing PassTheSalt ...' in result.output
            assert 'Successfully initialized PassTheSalt!' in result.output

            pts = PassTheSalt.read('passthesalt')
            assert pts.config.owner == 'John Smith'
            assert pts.config.master
            assert pts.config.master.validate('password')

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt']
            )
            assert result.exit_code == 2
            assert 'Missing command.' in result.output

    def test_pts_add(self):
        runner = CliRunner()

        with runner.isolated_filesystem():
            pts = PassTheSalt()
            pts.config.master = Master.with_validation('password')
            pts.save('passthesalt')

            # add something that can be added
            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'add', '--type', 'raw'],
                input='test\nsalt\ny\nn\n'
            )
            assert result.exit_code == 0
            assert 'Secret stored!' in result.output

            pts = PassTheSalt.read('passthesalt')
            assert 'test' in pts
            assert isinstance(pts['test'], Generatable)
            assert pts['test'].salt == 'salt'

            # add something and retrieve it
            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'add', '--type', 'raw', '--no-clipboard'],
                input='test2\nsalt\ny\ny\npassword'
            )
            assert result.exit_code == 0
            assert 'Secret stored!' in result.output
            assert 'M%J+hUIcYqe=LSDtSq0d' in result.output

            # add something that is already added
            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'add'],
                input='test\n'
            )
            assert result.exit_code == 1
            assert 'Label "test" already exists' in result.output

    def test_pts_encrypt(self):
        runner = CliRunner()

        with runner.isolated_filesystem():
            pts = PassTheSalt().with_master('password')
            pts.save('passthesalt')

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'encrypt'],
                input='test\nsecret\nsecret\npassword\n'
            )

            assert result.exit_code == 0
            assert 'Secret stored!' in result.output

            pts = PassTheSalt.read('passthesalt')
            assert 'test' in pts
            assert isinstance(pts['test'], Encrypted)

    def test_pts_get(self):
        runner = CliRunner()

        with runner.isolated_filesystem():
            pts = PassTheSalt().with_master('password')
            pts.config.master = Master.with_validation('password')
            pts.add('test', Generatable('salt'))
            pts.add('test2', Encrypted.with_secret('verysecret'))
            pts.save('passthesalt')

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'get', '--no-clipboard'],
                input='test\npasswor\npasswor\npasswor'
            )
            assert result.exit_code == 1
            assert 'Error: three incorrect attempts.' in result.output

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'get', '--no-clipboard'],
                input='test\npasswor\npassword'
            )
            assert result.exit_code == 0
            assert 'M%J+hUIcYqe=LSDtSq0d' in result.output

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'get', '--no-clipboard'],
                input='test\npassword\n'
            )
            assert result.exit_code == 0
            assert 'M%J+hUIcYqe=LSDtSq0d' in result.output

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'get', '--no-clipboard'],
                input='test2\npassword\n'
            )
            assert result.exit_code == 0
            assert 'verysecret' in result.output

    def test_pts_ls(self):
        runner = CliRunner()

        with runner.isolated_filesystem():
            pts = PassTheSalt().with_master('password')
            pts.save('passthesalt')

            result = runner.invoke(cli, ['--path', 'passthesalt', 'ls'])
            assert result.exit_code == 0
            assert 'No stored secrets.' in result.output

            pts = PassTheSalt.read('passthesalt').with_master('password')
            pts.add('test', Generatable('salt'))
            pts.add('test2', Encrypted.with_secret('verysecret'))
            pts.save('passthesalt')

            result = runner.invoke(cli, ['--path', 'passthesalt', 'ls', '--no-header'])
            assert result.exit_code == 0
            assert result.output == 'test\ntest2\n'

            result = runner.invoke(cli, ['--path', 'passthesalt', 'ls', '-v'])
            assert result.exit_code == 0
            assert result.output == 'Label    Kind\n' \
                                    '-------  -----------\n' \
                                    'test     generatable\n' \
                                    'test2    encrypted\n'

    def test_pts_rm(self):
        runner = CliRunner()

        with runner.isolated_filesystem():
            pts = PassTheSalt().with_master('password')
            pts.add('test', Generatable('salt'))
            pts.save('passthesalt')

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'rm'],
                input='test\ny\n'
            )
            assert result.exit_code == 0
            assert 'Removing "test"' in result.output

            pts = PassTheSalt.read('passthesalt')
            assert 'test' not in pts

            pts.add('test1', Generatable('salt'))
            pts.add('test2', Generatable('salt'))
            pts.add('test3', Generatable('salt'))
            pts.save('passthesalt')

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'rm', 'derp']
            )
            assert result.exit_code == 1
            assert result.output == 'Error: unable to resolve pattern "derp"\n'

            result = runner.invoke(
                cli,
                ['--path', 'passthesalt', 'rm', '^test\d$'],
                input='y\n'
            )
            assert result.exit_code == 0
            assert 'Removing "test1"' in result.output
            assert 'Removing "test2"' in result.output
            assert 'Removing "test3"' in result.output

    def test_pts_mv(self):
        runner = CliRunner()

        with runner.isolated_filesystem():
            pts = PassTheSalt().with_master('password')
            pts.add('test', Generatable('salt'))
            pts.save('passthesalt')

            result = runner.invoke(cli, ['--path', 'passthesalt', 'mv', 'test', 'test2'])
            assert result.exit_code == 0
            assert '"test" relabeled to "test2"!' in result.output

            pts = PassTheSalt.read('passthesalt')
            assert 'test' not in pts
            assert 'test2' in pts
            assert pts['test2'].to_dict(modified=False) == \
                Generatable('salt').to_dict(modified=False)
            assert pts['test2'] == Generatable('salt')

            pts.add('test', Generatable('salt'))
            pts.save('passthesalt')

            result = runner.invoke(cli, ['--path', 'passthesalt', 'mv', 'test', 'test2'])
            assert result.exit_code == 1
            assert 'Error: "test2" already exists' in result.output
