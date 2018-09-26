"""
A command line interface for PassTheSalt.
"""

import os
import re
import subprocess
import sys

import click
import pyperclip
from tabulate import tabulate

from passthesalt import (Algorithm, Encrypted, Generatable, LabelError,
                         Login, Master, PassTheSalt, __version__)


class URLParamType(click.ParamType):
    """
    A click URL parameter type.
    """

    name = 'url'

    def convert(self, value, param, ctx):
        """
        Process the entered URL, stripping it of the http prefix.
        """
        temp = re.sub(r'[hH][tT]{2}[pP][sS]?://', '', value).rstrip('/')
        if '.' in temp[1:-1]:
            return temp
        else:
            self.fail('"{}" is not a valid url'.format(value), param, ctx)


URL = URLParamType()
DEFAULT_PATH = os.path.expanduser('~/.passthesalt')


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


@click.group(context_settings={'help_option_names': ['-h', '--help']}, invoke_without_command=True)
@click.version_option(__version__, '-v', '--version', prog_name='passthesalt',
                      message='%(prog)s %(version)s')
@click.option('--path', '-p', type=click.Path(), default=DEFAULT_PATH,
              help='The path to the PassTheSalt store.')
@click.pass_context
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
        pts = PassTheSalt.read(path)
    except OSError:
        pass

    if pts is None:
        click.echo('Initializing PassTheSalt ...')
        pts = PassTheSalt()
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
        'pts': pts.with_master(get_master_from_user),
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
