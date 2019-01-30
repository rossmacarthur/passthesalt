"""
A command line interface for PassTheSalt.
"""

import datetime
import json
import os
import subprocess
import sys
from functools import wraps

import click
import pyperclip
import serde
import validators
from click import confirm, echo, prompt
from tabulate import tabulate

from passthesalt import Algorithm, Encrypted, Generatable, Login, Master, PassTheSalt
from passthesalt.exceptions import LabelError, PassTheSaltError
from passthesalt.remote import Stow


class DomainParamType(click.ParamType):
    """
    A click Domain parameter type.
    """

    name = 'domain'

    def convert(self, value, param, ctx):
        """
        Validate the entered value is a domain.
        """
        if not validators.domain(value):
            self.fail(f'{value} is not a valid domain', param, ctx)

        return value


class UrlParamType(click.ParamType):
    """
    A click URL parameter type.
    """

    name = 'url'

    def convert(self, value, param, ctx):
        """
        Validate the entered value is a URL.
        """
        if not validators.url(value):
            self.fail(f'{value} is not a valid URL', param, ctx)

        return value


DOMAIN = DomainParamType()
URL = UrlParamType()
DEFAULT_PATH = os.path.expanduser('~/.passthesalt')
DEFAULT_REMOTE_PATH = os.path.expanduser('~/.passthesalt.remote')


def bail(message):
    """
    Abort the CLI with a message.
    """
    raise click.ClickException(message)


def handle_passthesalt_errors(f):
    """
    Translate PassTheSaltErrorErrors to ClickExceptions.

    Args:
        f (function): the function to decorate.

    Raises:
        click.ClickException: when the function raises a PassTheSaltError.

    Returns:
        function: the decorated function.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except PassTheSaltError as e:
            bail(e.message)

    return decorated_function


def clear_clipboard(timeout):
    """
    Clear the clipboard after a timeout.

    Args:
        timeout (int): the timeout.
    """
    code = f"import pyperclip, time; time.sleep({timeout}); pyperclip.copy('');"
    command = f'{sys.executable} -c "{code}"'
    subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=True
    )


def copy_to_clipboard(text, timeout=None):
    """
    Copy the given text to clipboard.

    Args:
        text (str): the text to copy to the clipboard.
        timeout (int): clear the clipboard after this amount of seconds.
    """
    pyperclip.copy(text)

    if timeout:
        clear_clipboard(timeout)


def ask_user_for_master(pts):
    """
    Prompt the user for the master password. Bail after 3 attempts.

    Args:
        pts (PassTheSalt): the PassTheSalt instance calling this function.

    Returns:
        str: the master password.
    """
    for i in range(3):
        master = prompt('Enter master password', hide_input=True)

        if pts.config.master.is_valid(master):
            return master

        echo('Error: invalid master password', err=True)

    raise bail('three incorrect attempts')


def ask_user_for_auth(remote):
    """
    Prompt the user for the username and password for the remote store.

    Args:
        remote (Remote): the remote instance.

    Returns:
        (str, str): the username and password.
    """
    echo('Authentication is required')
    name = prompt('Enter username')
    password = prompt('Enter password', hide_input=True)

    return name, password


def read_or_init_remote(path):
    """
    Read the Remote from the given path or initialize a new Remote.

    Args:
        path (str): the path to the Remote.

    Returns:
        Remote: the initialized or read Remote.
    """
    try:
        remote = Stow.from_path(path).with_auth(ask_user_for_auth)
    except OSError:
        echo('Initializing PassTheSalt remote configuration ...')
        remote = Stow(
            location=prompt('Enter location URL', type=URL),
            token_location=prompt('Enter token renew URL', type=URL)
        ).with_auth(ask_user_for_auth)

    return remote


def pts_ls_(pts, label=None, kind=None, header=True, verbose=1):
    """
    List the secrets in a PassTheSalt store.

    Args:
        pts (PassTheSalt): the PassTheSalt store.
        label (str): a label to filter on.
        kind (str): the kind to filter on (generatable or encrypted)
        header (bool): whether to print the table header.
        verbose (int): the verbosity count that determines how much information
            for each secret is displayed.
    """
    labels = pts.labels(pattern=label)

    if not labels:
        echo('No stored secrets', err=True)
    else:
        secrets = []

        for label in sorted(labels):
            secret = pts.get(label)

            if not kind or secret.kind == kind:
                secrets.append(secret.display()[:verbose + 1])

        if header:
            kwargs = {
                'headers': ('Label', 'Kind', 'Modified', 'Salt')[:verbose + 1]
            }
        else:
            kwargs = {
                'tablefmt': 'plain',
            }

        echo(tabulate(secrets, **kwargs))


@click.group(
    context_settings={'help_option_names': ['-h', '--help']},
    invoke_without_command=True
)
@click.version_option(
    None,
    '-v', '--version',
    prog_name='passthesalt',
    message='%(prog)s %(version)s'
)
@click.option(
    '--path', '-p',
    type=click.Path(),
    default=DEFAULT_PATH,
    help='The path to the PassTheSalt store.'
)
@click.pass_context
@handle_passthesalt_errors
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
        pts = PassTheSalt.from_path(path).with_master(ask_user_for_master).with_path(path)
    except OSError:
        pass

    # The only time pts is allowed to be None is if we are pulling a store.
    if ctx.invoked_subcommand != 'pull':
        if pts is None:
            echo('Initializing PassTheSalt ...')
            pts = PassTheSalt().with_master(ask_user_for_master).with_path(path)
            pts.config.owner = prompt('Please enter your name')
            pts.config.master = Master(prompt(
                'Please enter the master password',
                confirmation_prompt=True,
                hide_input=True
            ))
            pts.save()
            echo('Successfully initialized PassTheSalt!')
        elif ctx.invoked_subcommand is None:
            echo(ctx.get_help())

    ctx.obj = pts or path


@cli.command('add')
@click.argument('label', required=False)
@click.option(
    '--type', '-t',
    type=click.Choice(['raw', 'login']),
    default='login',
    help='The type of generated secret.'
)
@click.option(
    '--length', '-l',
    type=int,
    help='The length of the generated secret.'
)
@click.option(
    '--version', '-v',
    type=click.Choice(['0', '1']),
    default='1',
    show_default=True,
    help='The algorithm version to use.'
)
@click.option(
    '--clipboard/--no-clipboard',
    default=True,
    show_default=True,
    help='Whether to copy the secret to the clipboard or print it out.'
)
@click.pass_context
@handle_passthesalt_errors
def pts_add(ctx, label, type, length, version, clipboard):
    """
    Add a secret.

    Add a generatable secret with label LABEL to the PassTheSalt store.
    """
    pts = ctx.obj

    if not label:
        label = prompt('Enter label')

    if pts.contains(label):
        bail(f'{label!r} already exists')

    algorithm = Algorithm(version=int(version), length=length)

    if type == 'login':
        secret = Login(
            domain=prompt('Enter domain name', type=DOMAIN),
            username=prompt('Enter username'),
            iteration=prompt('Enter iteration', default=0),
            algorithm=algorithm
        )
    else:
        secret = Generatable(
            salt=prompt('Enter salt'),
            algorithm=algorithm
        )

    confirm(f'Store {secret.salt!r} as {label!r}?', abort=True)
    pts.add(label, secret)
    pts.save()
    echo(f'Stored {label!r}!')

    if confirm('\nRetrieve secret?'):
        ctx.invoke(pts_get, label=label, clipboard=clipboard)


@cli.command('encrypt')
@click.argument('label', required=False)
@click.option('--secret', '-s', help='The secret to store.')
@click.pass_obj
@handle_passthesalt_errors
def pts_encrypt(pts, label, secret):
    """
    Encrypt a secret.

    Add an encrypted secret with label LABEL to the PassTheSalt store.
    """
    if not label:
        label = prompt('Enter label')

    if pts.contains(label):
        bail(f'{label!r} already exists')

    if not secret:
        secret = prompt('Enter secret', confirmation_prompt=True, hide_input=True)

    pts.add(label, Encrypted(secret))
    pts.save()
    echo(f'Stored {label!r}!')


@cli.command('get')
@click.argument('label', required=False)
@click.option(
    '--clipboard/--no-clipboard',
    default=True,
    show_default=True,
    help='Whether to copy the secret to the clipboard or print it out.'
)
@click.pass_obj
@handle_passthesalt_errors
def pts_get(pts, label, clipboard):
    """
    Retrieve a secret.

    Get the secret matching the label LABEL.
    """
    if not label:
        label = prompt('Enter label')

    label = pts.resolve(pattern=label)
    secret = pts.get(label).get()

    if clipboard:
        copy_to_clipboard(secret, timeout=20)
        echo('Secret copied to clipboard.')
    else:
        echo(secret)


@cli.command('ls')
@click.argument('label', required=False)
@click.option(
    '--kind', '-k',
    type=click.Choice(['encrypted', 'generatable']),
    help='Filter by type of secret.'
)
@click.option(
    '--header/--no-header',
    default=True,
    help='Whether to display the table header.'
)
@click.option(
    '--verbose', '-v',
    count=True,
    help='Increase amount information displayed.'
)
@click.pass_obj
@handle_passthesalt_errors
def pts_ls(pts, label, kind, header, verbose):
    """
    List the secrets.
    """
    pts_ls_(pts, label=label, kind=kind, header=header, verbose=verbose)


@cli.command('rm')
@click.argument('label', required=False)
@click.option(
    '--regex', '-r',
    is_flag=True,
    help='Match labels using LABEL as a regex pattern.'
)
@click.option(
    '--force', '-f',
    is_flag=True,
    help='Do not ask for confirmation before removing.'
)
@click.pass_obj
@handle_passthesalt_errors
def pts_rm(pts, label, regex, force):
    """
    Remove a secret.

    Completely remove the secret(s) matching the label LABEL from the
    PassTheSalt store. Removing encrypted secrets will require the master
    password.
    """
    if not label:
        label = prompt('Enter label')

    try:
        if regex:
            label = pts.resolve(pattern=label)
    except LabelError:
        labels = pts.labels(pattern=label)

        if not labels:
            raise

        labels_display = ', '.join(repr(label) for label in labels)

        if not force:
            confirm(f'Remove {labels_display}?', abort=True)

        for label in labels:
            pts.remove(label)

        pts.save()
        echo(f'Removed {labels_display}!')
    else:
        if not pts.contains(label):
            bail(f'{label!r} does not exist')

        if not force:
            confirm(f'Remove {label!r}?', abort=True)

        pts.remove(label)
        pts.save()
        echo(f'Removed {label!r}!')


@cli.command('mv')
@click.argument('label')
@click.argument('new-label', metavar='NEW-LABEL')
@click.pass_obj
@handle_passthesalt_errors
def pts_mv(pts, label, new_label):
    """
    Relabel a secret.

    Give the secret matching the label LABEL a new label NEW-LABEL.
    """
    pts.move(label, new_label)
    pts.save()
    echo(f'Renamed {label!r} as {new_label!r}!')


@cli.command('push')
@click.option(
    '--path', '-p',
    type=click.Path(),
    default=DEFAULT_REMOTE_PATH,
    help='The path to the PassTheSalt remote configuration.'
)
@click.option(
    '--force', '-f',
    is_flag=True,
    help='Ignore any conflicts.'
)
@click.pass_obj
@handle_passthesalt_errors
def pts_push(pts, path, force):
    """
    Update the remote store.
    """
    remote = read_or_init_remote(path)
    remote.put(pts, force=force)
    remote.to_path(path)
    echo('Successfully pushed to remote store')


@cli.command('pull')
@click.option(
    '--path', '-p',
    type=click.Path(),
    default=DEFAULT_REMOTE_PATH,
    help='The path to the PassTheSalt remote configuration.'
)
@click.option(
    '--force', '-f',
    is_flag=True,
    help='Ignore any conflicts.'
)
@click.pass_obj
@handle_passthesalt_errors
def pts_pull(pts, path, force):
    """
    Retrieve a remote store.
    """
    pts_path = getattr(pts, 'path', pts)
    remote = read_or_init_remote(path)
    remote_pts = remote.get().with_path(pts_path)
    remote.to_path(path)

    if not isinstance(pts, PassTheSalt) or force or remote_pts.modified > pts.modified:
        remote_pts.save()
        echo('Successfully pulled remote store')
    elif remote_pts == pts:
        echo('Already up to date')
    else:
        bail('local version is newer than the remote')


@cli.command('diff')
@click.option(
    '--path', '-p',
    type=click.Path(),
    default=DEFAULT_REMOTE_PATH,
    help='The path to a local PassTheSalt store or a remote configuration.'
)
@click.option(
    '--kind', '-k',
    type=click.Choice(['encrypted', 'generatable']),
    help='Filter by type of secret.'
)
@click.option(
    '--verbose', '-v',
    count=True,
    help='Increase amount information displayed.'
)
@click.pass_obj
@handle_passthesalt_errors
def pts_diff(pts, path, kind, verbose):
    """
    Compare two stores.
    """
    try:
        remote = read_or_init_remote(path)
        other_pts = remote.get().with_path(pts.path)
        remote.to_path(path)
    except serde.exceptions.DeserializationError:
        other_pts = PassTheSalt.from_path(path)

    diff_left = pts._diff(other_pts)
    diff_right = other_pts._diff(pts)

    if diff_left.labels():
        echo('Local store has the following extra/modified secrets:')
        pts_ls_(diff_left, kind=kind, header=False, verbose=verbose)

    if diff_right.labels():
        if diff_left.labels():
            echo()

        echo('Remote store has the following extra/modified secrets:')
        pts_ls_(diff_right, kind=kind, header=False, verbose=verbose)

    if diff_left.labels() or diff_right.labels():
        exit(1)


@cli.command('migrate', hidden=True)
@click.option(
    '-i', '--input-file',
    type=click.Path(exists=True, dir_okay=False),
    help='The input data file.'
)
@click.pass_obj
@handle_passthesalt_errors
def pts_migrate(pts, input_file):
    """
    Load secrets from a PassTheSalt 2.3.x dumped database.
    """
    if input_file:
        with open(input_file, 'r') as f:
            raw = json.load(f)
    else:
        raw = json.loads(sys.stdin.read())

    for label, raw_secret in raw.items():
        modified = datetime.datetime.strptime(raw_secret['modified'], '%Y%m%d')

        if raw_secret['type'] == 'generatable':
            legacy_algorithm = Algorithm(version=0)

            try:
                domain, username, iteration = raw_secret['salt'].split('|')
                secret = Login(
                    modified=modified,
                    domain=domain,
                    username=username,
                    iteration=int(iteration),
                    algorithm=legacy_algorithm
                )
            except Exception:
                secret = Generatable(
                    modified=modified,
                    salt=raw_secret['salt'],
                    algorithm=legacy_algorithm
                )

            pts.add(label, secret)

        elif raw_secret['type'] == 'encrypted':
            secret = Encrypted(
                raw_secret['secret'],
                modified=modified
            )
            pts.add(label, secret)

        else:
            bail(f'unknown secret type {raw_secret["type"]}')

        echo(f'Migrated {label!r}')

    pts.save()
    echo('Success!')
