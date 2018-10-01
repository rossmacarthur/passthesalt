"""
A command line interface for PassTheSalt.
"""

import datetime
import json
import os
import re
import subprocess
import sys

import click
import pyperclip
from tabulate import tabulate

from passthesalt import (Algorithm, Encrypted, Error, Generatable, LabelError,
                         Login, Master, PassTheSalt, Stow, __version__)


class URLParamType(click.ParamType):
    """
    A click URL parameter type.
    """

    name = 'url'

    def __init__(self, strip_scheme=True):
        """
        Create a new URLParamType.

        Args:
            strip_scheme (bool): whether to remove the URL scheme.
        """
        self.strip_scheme = strip_scheme

    def convert(self, value, param, ctx):
        """
        Process the entered URL, stripping it of the http prefix.
        """
        temp = re.sub(r'[hH][tT]{2}[pP][sS]?://', '', value).rstrip('/')
        if '.' in temp[1:-1]:
            if self.strip_scheme:
                return temp
            else:
                return value
        else:
            self.fail('"{}" is not a valid url'.format(value), param, ctx)


URL = URLParamType()
URL_WITH_SCHEME = URLParamType(strip_scheme=False)
DEFAULT_PATH = os.path.expanduser('~/.passthesalt')
DEFAULT_REMOTE_PATH = os.path.expanduser('~/.passthesalt.remote')


def handle_errors(func):
    """
    Decorator to translate passthesalt Errors to ClickExceptions.

    Args:
        func (Callable): the function to decorate.

    Raises:
        click.ClickException: raise when the function raises an Error.

    Returns:
        Callable: the decorated function.
    """
    def decorated_function(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Error as e:
            raise click.ClickException(e.message)

    return decorated_function


def clear_clipboard(timeout):
    """
    Clear the clipboard after a timeout.

    Args:
        timeout (int): the timeout.
    """
    code = "import pyperclip, time; time.sleep({}); pyperclip.copy('');".format(timeout)
    command = ('{python} -c "{code}"'.format(python=sys.executable, code=code))
    subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=True
    )


def copy_to_clipboard(text, timeout=None):
    """
    Copy text to clipboard.

    Args:
        text (Text): the text to copy to the clipboard.
        timeout (int): clear the clipboard after this amount of seconds.
    """
    pyperclip.copy(text)
    if timeout:
        clear_clipboard(timeout)


def get_master_from_user(pts):
    """
    Prompt the user for the master password. Bail after 3 attempts.

    Args:
        pts (PassTheSalt): the PassTheSalt instance calling this function.

    Raises:
        click.ClickException: when the user could not provide a valid master
            password.

    Returns:
        Text: the master password.
    """
    for i in range(3):
        master = click.prompt('Enter master password', hide_input=True)

        if pts.config.master.validate(master):
            return master

        click.echo('Error: invalid master password.', err=True)

    raise click.ClickException('three incorrect attempts.')


def get_auth_from_user(remote):
    """
    Prompt the user for the username and password from the remote store.

    Args:
        remote (Remote): the remote instance.

    Returns:
        Tuple[Text, Text]: the username and password.
    """
    click.echo('Authentication is required.')
    name = click.prompt('Enter username')
    password = click.prompt('Enter password', hide_input=True)
    return (name, password)


@click.group(context_settings={'help_option_names': ['-h', '--help']}, invoke_without_command=True)
@click.version_option(__version__, '-v', '--version', prog_name='passthesalt',
                      message='%(prog)s %(version)s')
@click.option('--path', '-p', type=click.Path(), default=DEFAULT_PATH,
              help='The path to the PassTheSalt store.')
@click.pass_context
@handle_errors
def cli(ctx, path):
    """
    \b
        ____                 ________        _____       ____
       / __ \____  _________/_  __/ /_  ___ / ___/____ _/ / /_
      / /_/ / __ `/ ___/ ___// / / __ \/ _ \\\\__ \/ __ `/ / __/
     / ____/ /_/ (__  |__  )/ / / / / /  __/__/ / /_/ / / /_
    /_/    \__,_/____/____//_/ /_/ /_/\___/____/\__,_/_/\__/

    A deterministic password generation and password storage system.
    """
    pts = None

    try:
        pts = PassTheSalt.read(path).with_master(get_master_from_user)
    except OSError:
        pass

    if ctx.invoked_subcommand != 'pull':
        if pts is None:
            click.echo('Initializing PassTheSalt ...')
            pts = PassTheSalt().with_master(get_master_from_user)
            pts.config.owner = click.prompt('Please enter your name')

            if click.confirm('Use master password validation?'):
                master = click.prompt('Please enter the master password',
                                      confirmation_prompt=True, hide_input=True)
                pts.config.master = Master.with_validation(master)

            pts.save(path)
            click.echo('Successfully initialized PassTheSalt!')
        elif ctx.invoked_subcommand is None:
            ctx.fail('Missing command.')

    ctx.obj = {
        'pts': pts,
        'path': path
    }


@cli.command('add')
@click.argument('label', required=False)
@click.option('--type', '-t', type=click.Choice(['raw', 'login']), default='login',
              help='The type of generated secret.')
@click.option('--length', '-l', type=int,
              help='The length of the generated secret.')
@click.option('--version', '-v', type=click.Choice(['0', '1']), default='1', show_default=True,
              help='The algorithm version to use.')
@click.option('--clipboard/--no-clipboard', default=True, show_default=True,
              help='Whether to copy the secret to the clipboard or print it out.')
@click.pass_context
@handle_errors
def pts_add(ctx, label, type, length, version, clipboard):
    """
    Add a secret.

    Add a generatable secret with label LABEL to the PassTheSalt store.
    """
    if not label:
        label = click.prompt('Enter label')

    version = int(version)

    pts = ctx.obj['pts']
    path = ctx.obj['path']

    if label in pts:
        click.echo('Label "{}" already exists.'.format(label))
        raise click.Abort()

    algorithm = Algorithm(version=version, length=length)

    if type == 'login':
        domain = click.prompt('Enter domain name', type=URL)
        username = click.prompt('Enter username')
        iteration = click.prompt('Enter iteration', default=0)
        secret = Login(domain, username, iteration=iteration, algorithm=algorithm)
    else:
        salt = click.prompt('Enter salt')
        secret = Generatable(salt, algorithm=algorithm)

    click.confirm('Store "{}" as "{}"'.format(secret.salt, label), abort=True)

    pts[label] = secret
    pts.save(path)
    click.echo('Secret stored!')

    if click.confirm('\nRetrieve secret?'):
        ctx.invoke(pts_get, label=label, clipboard=clipboard)


@cli.command('encrypt')
@click.argument('label', required=False)
@click.option('--secret', '-s', help='The secret to store.')
@click.pass_obj
@handle_errors
def pts_encrypt(obj, label, secret):
    """
    Encrypt a secret.

    Add an encrypted secret with label LABEL to the PassTheSalt store.
    """
    if not label:
        label = click.prompt('Enter label')

    pts = obj['pts']
    path = obj['path']

    if not secret:
        secret = click.prompt('Enter secret to store', confirmation_prompt=True, hide_input=True)

    pts[label] = Encrypted.with_secret(secret)
    pts.save(path)
    click.echo('Secret stored!')


@cli.command('get')
@click.argument('label', required=False)
@click.option('--clipboard/--no-clipboard', default=True, show_default=True,
              help='Whether to copy the secret to the clipboard or print it out.')
@click.pass_obj
@handle_errors
def pts_get(obj, label, clipboard):
    """
    Retrieve a secret.

    Get the secret matching the label LABEL.
    """
    if not label:
        label = click.prompt('Enter label')

    pts = obj['pts']

    secret = pts[label].get()

    if clipboard:
        copy_to_clipboard(secret, timeout=20)
        click.echo('Secret copied to clipboard.')
    else:
        click.echo(secret)


@cli.command('ls')
@click.option('--pattern', '-r', help='Regex pattern to filter the labels.')
@click.option('--prefix', '-p', help='Prefix to filter the labels.')
@click.option('--kind', '-k', type=click.Choice(['encrypted', 'generatable']))
@click.option('--header/--no-header', default=True, help='Whether to display the table header.')
@click.option('--verbose', '-v', count=True, help='Increase amount information displayed.')
@click.pass_obj
@handle_errors
def pts_ls(obj, pattern, prefix, kind, header, verbose):
    """
    List the secrets.
    """
    pts = obj['pts']

    labels = pts.labels(pattern=pattern, prefix=prefix)

    if not labels:
        click.echo('No stored secrets.', err=True)
    else:
        table = []

        for label in sorted(labels):
            secret = pts[label]
            if kind is None or secret.kind == kind:
                table.append(secret.display()[:verbose + 1])

        if header:
            kwargs = {
                'headers': ('Label', 'Kind', 'Modified', 'Salt')[:verbose + 1]
            }
        else:
            kwargs = {
                'tablefmt': 'plain',
            }

        click.echo(tabulate(table, **kwargs))


@cli.command('rm')
@click.argument('label', required=False)
@click.option('--force', '-f', is_flag=True, help='Do not ask for confirmation before removing.')
@click.pass_obj
@handle_errors
def pts_rm(obj, label, force):
    """
    Remove a secret.

    Completely remove the secret matching the label LABEL from the PassTheSalt
    store. Removing encrypted secrets will require the master password.
    """
    if not label:
        label = click.prompt('Enter label')

    pts = obj['pts']
    path = obj['path']

    try:
        label = pts.resolve(pattern=label)

        if not force:
            click.confirm('Remove "{}"?'.format(label), abort=True)

        click.echo('Removing "{}"'.format(label))
        del pts[label]
        pts.save(path)
        return
    except LabelError as e:
        labels = pts.labels(pattern=label)

        if not labels:
            raise click.ClickException(e)

    if not force:
        click.echo('Found {} matching secrets: {}'.format(len(labels), ', '.join(labels)))
        click.confirm('Remove all?', abort=True)

    for label in labels:
        click.echo('Removing "{}"'.format(label))
        del pts[label]

    pts.save(path)


@cli.command('mv')
@click.argument('label')
@click.argument('new-label', metavar='NEW-LABEL')
@click.pass_obj
@handle_errors
def pts_mv(obj, label, new_label):
    """
    Relabel a secret.

    Give the secret matching the label LABEL a new label NEW-LABEL.
    """
    pts = obj['pts']
    path = obj['path']

    try:
        pts.relabel(label, new_label)
        click.echo('"{}" relabeled to "{}"!'.format(label, new_label))
        pts.save(path)
    except LabelError as e:
        raise click.ClickException(e)


@cli.command('push')
@click.option('--path', '-p', type=click.Path(), default=DEFAULT_REMOTE_PATH,
              help='The path to the PassTheSalt remote configuration.')
@click.option('--force', '-f', is_flag=True,
              help='Ignore any conflicts.')
@click.pass_obj
@handle_errors
def pts_push(obj, path, force):
    """
    Update the remote store.
    """
    pts = obj['pts']

    try:
        remote = Stow.read(path).with_auth(get_auth_from_user)
    except OSError:
        click.echo('Initializing PassTheSalt remote configuration ...')
        location = click.prompt('Enter location URL', type=URL_WITH_SCHEME)
        token_location = click.prompt('Enter token renew URL', type=URL_WITH_SCHEME)
        remote = Stow(location, token_location).with_auth(get_auth_from_user)

    remote.put(pts, force=force)
    remote.save(path)
    click.echo('Successfully pushed to remote store.')


@cli.command('pull')
@click.option('--path', '-p', type=click.Path(), default=DEFAULT_REMOTE_PATH,
              help='The path to the PassTheSalt remote configuration.')
@click.option('--force', '-f', is_flag=True,
              help='Ignore any conflicts.')
@click.pass_obj
@handle_errors
def pts_pull(obj, path, force):
    """
    Retrieve a remote store.
    """
    pts = obj['pts']
    pts_path = obj['path']

    try:
        remote = Stow.read(path).with_auth(get_auth_from_user)
    except OSError:
        click.echo('Initializing PassTheSalt remote configuration ...')
        location = click.prompt('Enter location URL', type=URL_WITH_SCHEME)
        token_location = click.prompt('Enter token renew URL', type=URL_WITH_SCHEME)
        remote = Stow(location, token_location).with_auth(get_auth_from_user)

    remote_pts = remote.get()
    remote.save(path)

    if not pts or force or remote_pts.modified > pts.modified:
        remote_pts.save(pts_path)
        click.echo('Successfully pulled remote store.')
    elif remote_pts == pts:
        click.echo('Already up to date.')
    else:
        raise click.ClickException('The local version is newer than the remote.')


@cli.command('migrate', hidden=True)
@click.option('-i', '--input-file', type=click.Path(exists=True, dir_okay=False),
              help='The input data file.')
@click.pass_obj
@handle_errors
def pts_migrate(obj, input_file):
    """
    Load secrets from a PassTheSalt 2.3.x dumped database.
    """
    pts = obj['pts']
    path = obj['path']

    if input_file:
        with open(input_file, 'r') as f:
            raw = json.load(f)
    else:
        raw = json.loads(sys.stdin.read())

    for label, raw_secret in raw.items():
        modified = datetime.datetime.strptime(raw_secret['modified'], '%Y%m%d')

        if raw_secret['type'] == 'generatable':
            legacy_algorithm = Algorithm(version=None)
            domain, username, iteration = raw_secret['salt'].split('|')
            iteration = int(iteration) or None
            secret = Login(domain, username, iteration=iteration, algorithm=legacy_algorithm)
            pts[label] = secret

            # override modified time with original
            secret.modified = modified

        elif raw_secret['type'] == 'encrypted':
            secret = Encrypted.with_secret(raw_secret['secret'])
            pts[label] = secret

            # override modified time with original
            secret.modified = modified

        else:
            raise click.ClickException('unknown secret type "{}"'.format(raw_secret['type']))

        click.echo('Migrated "{}"'.format(label))

    pts.save(path)
