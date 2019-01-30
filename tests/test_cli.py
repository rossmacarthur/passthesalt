import click
from click.testing import CliRunner
from pytest import raises

from passthesalt import Config, Encrypted, Generatable, Login, Master, PassTheSalt
from passthesalt.cli import bail, cli, handle_passthesalt_errors
from passthesalt.exceptions import PassTheSaltError


def test_bail():
    with raises(click.ClickException) as e:
        bail('test')
        assert e.message == 'test'


def test_handle_passthesalt_errors():

    @handle_passthesalt_errors
    def raise_passthesalt_error():
        raise PassTheSaltError('test')

    with raises(click.ClickException) as e:
        raise_passthesalt_error()
        assert e.message == 'test'


def test_cli_initializing():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            ['--path', 'passthesalt'],
            input='John Smith\npassword\npassword\n'
        )
        assert result.exit_code == 0
        assert 'Initializing PassTheSalt ...' in result.output
        assert 'Successfully initialized PassTheSalt!' in result.output

        pts = PassTheSalt.from_path('passthesalt')
        assert pts.config.owner == 'John Smith'
        assert pts.config.master
        assert pts.config.master.is_valid('password')


def test_cli_missing_command():
    runner = CliRunner()

    with runner.isolated_filesystem():
        PassTheSalt().to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt']
        )
        assert result.exit_code == 0
        assert 'Usage: cli [OPTIONS] COMMAND [ARGS]...' in result.output


def test_pts_add_raw():
    runner = CliRunner()

    with runner.isolated_filesystem():
        PassTheSalt().to_path('passthesalt')
        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'add', '--type', 'raw'],
            input='Example\nsalt\ny\nn\n'
        )
        assert result.exit_code == 0
        assert "Stored 'Example'!" in result.output

        pts = PassTheSalt.from_path('passthesalt')
        assert isinstance(pts.get('Example'), Generatable)
        assert pts.get('Example').salt == 'salt'


def test_pts_add_login():
    runner = CliRunner()

    with runner.isolated_filesystem():
        PassTheSalt().to_path('passthesalt')
        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'add'],
            input='Example\nwww\nwww.test.com\ntest\n\ny\nn\n'
        )
        assert result.exit_code == 0
        assert "Stored 'Example'!" in result.output

        pts = PassTheSalt.from_path('passthesalt')
        assert isinstance(pts.get('Example'), Login)
        assert pts.get('Example').salt == 'www.test.com|test|0'


def test_pts_add_exists():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'add'],
            input='Example\n'
        )
        assert result.exit_code == 1
        assert "'Example' already exists" in result.output


def test_pts_encrypt():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt(config=Config(master=Master('password')))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'encrypt'],
            input='Example\nsecret\nsecret\npassword\n'
        )
        assert result.exit_code == 0
        assert "Stored 'Example'!" in result.output

        pts = PassTheSalt.from_path('passthesalt').with_master('password')
        assert isinstance(pts.get('Example'), Encrypted)
        assert pts.get('Example').get() == 'secret'


def test_pts_encrypt_exists():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'encrypt'],
            input='Example\n'
        )
        assert result.exit_code == 1
        assert "'Example' already exists" in result.output


def test_pts_get_generated():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt(config=Config(master=Master('password')))
        pts.add('Example', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'get', '--no-clipboard'],
            input='Example\npassword\n'
        )
        assert result.exit_code == 0
        assert 'M%J+hUIcYqe=LSDtSq0d' in result.output


def test_pts_get_incorrect_master():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt(config=Config(master=Master('password')))
        pts.add('Example', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'get', '--no-clipboard'],
            input='Example\npasswor\npasswor\npasswor\n'
        )
        assert result.exit_code == 1
        assert 'three incorrect attempts' in result.output


def test_pts_get_encrypted():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt(config=Config(master=Master('password'))).with_master('password')
        pts.add('Example', Encrypted('verysecret'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'get', '--no-clipboard'],
            input='Example\npassword\n'
        )
        assert result.exit_code == 0
        assert 'verysecret' in result.output


def test_pts_ls_none():
    runner = CliRunner()

    with runner.isolated_filesystem():
        PassTheSalt().to_path('passthesalt')
        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'ls']
        )
        assert 'No stored secrets' in result.output


def test_pts_ls():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt().with_master('password')
        pts.add('Example1', Generatable(salt='salt'))
        pts.add('Example2', Encrypted('verysecret'))
        pts.to_path('passthesalt')
        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'ls', '-v']
        )
        expected = (
            'Label     Kind\n'
            '--------  -----------\n'
            'Example1  generatable\n'
            'Example2  encrypted\n'
        )
        assert result.output == expected


def test_pts_rm():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'rm'],
            input='Example\ny\n'
        )
        assert result.exit_code == 0
        assert "Removed 'Example'!" in result.output


def test_pts_rm_not_exists():
    runner = CliRunner()

    with runner.isolated_filesystem():
        PassTheSalt().to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'rm'],
            input='Example\n'
        )
        assert result.exit_code == 1
        assert "'Example' does not exist" in result.output


def test_pts_rm_multiple_not_exists():
    runner = CliRunner()

    with runner.isolated_filesystem():
        PassTheSalt().to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'rm', '--regex'],
            input='Example\n'
        )
        assert result.exit_code == 1
        assert "Error: unable to resolve pattern 'Example'" in result.output


def test_pts_rm_multiple():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt()
        pts.add('Example1', Generatable(salt='salt'))
        pts.add('Example2', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'rm', '--regex'],
            input='Example\ny\n'
        )
        assert result.exit_code == 0
        assert "Removed 'Example1', 'Example2'!" in result.output


def test_pts_mv():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt()
        pts.add('Example', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'mv', 'Example', 'Example2']
        )
        assert result.exit_code == 0
        assert "Renamed 'Example' as 'Example2'!" in result.output


def test_pts_diff():
    runner = CliRunner()

    with runner.isolated_filesystem():
        pts = PassTheSalt()
        pts.to_path('passthesalt_other')
        pts.add('Example', Generatable(salt='salt'))
        pts.to_path('passthesalt')

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt', 'diff', '--path', 'passthesalt_other']
        )
        assert result.exit_code == 1
        assert 'Local store has the following extra/modified secrets:\nExample' in result.output

        result = runner.invoke(
            cli,
            ['--path', 'passthesalt_other', 'diff', '--path', 'passthesalt']
        )
        assert result.exit_code == 1
        assert 'Remote store has the following extra/modified secrets:\nExample' in result.output
