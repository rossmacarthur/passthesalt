from __future__ import absolute_import, division, print_function, unicode_literals
import click
import os
import re
from passthesalt import PassTheSalt, to_clipboard, generate, __version__

click.disable_unicode_literals_warning = True

PATH = os.path.expanduser('~/.passthesalt')


class URLParamType(click.ParamType):
    name = 'url'

    def convert(self, value, param, ctx):
        temp = re.sub(r'https?://', '', value).rstrip('/')
        if '.' in temp[1:-1]:
            return temp
        else:
            self.fail('"{}" is not a valid url'.format(value), param, ctx)


URL = URLParamType()


def get_master_password(pts):
    master_password = click.prompt('Enter master password', hide_input=True)
    for i in range(2):
        if pts.master_valid(master_password):
            break
        click.echo('Error: invalid master password.')
        master_password = click.prompt('Enter master password', hide_input=True)
    else:
        click.echo('Error: three incorrect attempts.')
        raise click.Abort()
    return master_password


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(__version__, '-v', '--version', prog_name='passthesalt', message='%(prog)s %(version)s')
@click.pass_context
def cli(ctx):
    """
    \b
     ____                 _   _            ____        _ _
    |  _ \ __ _ ___ ___  | |_| |__   ___  / ___|  __ _| | |_
    | |_) / _` / __/ __| | __| '_ \ / _ \ \___ \ / _` | | __|
    |  __/ (_| \__ \__ \ | |_| | | |  __/  ___) | (_| | | |_
    |_|   \__,_|___/___/  \__|_| |_|\___| |____/ \__,_|_|\__|

    A deterministic password generation and password storage system.
    """
    pts = PassTheSalt()

    if os.path.isfile(PATH):
        pts.load(PATH)
    else:
        click.echo('Initializing Pass the Salt ... ')
        owner = click.prompt('Please enter your name')

        if click.confirm('Use master password validation?'):
            master_password = click.prompt('Please enter the master password',
                                           confirmation_prompt=True, hide_input=True)
            pts.initialize(owner, master_password)
        else:
            pts.initialize(owner)

        pts.save(PATH)
        click.echo('Successfully initialized Pass The Salt!\n')

    ctx.obj = pts


@cli.command('add')
@click.argument('label', required=False)
@click.option('--encrypt', '-e', is_flag=True, help='Store and encrypt a secret.')
@click.option('--clipboard/--no-clipboard', default=True,
              help='Whether to copy secret to clipboard or print it out (default: clipboard).')
@click.pass_context
def pts_add(ctx, label, encrypt, clipboard):
    """
    Store secret.

    LABEL is the unique label for the secret.
    """
    pts = ctx.obj

    if not label:
        label = click.prompt('Enter label for new secret')

    if pts.exists(label):
        click.echo('Label "{}" already exists.'.format(label))
        click.confirm('Update?', abort=True)

    master_password = None
    if encrypt:
        secret = click.prompt('Enter secret to store', confirmation_prompt=True, hide_input=True)
        master_password = get_master_password(pts)
        pts.store_encrypted(label, secret, master_password)
    else:
        domain = click.prompt('Enter domain name', type=URL)
        username = click.prompt('Enter username')
        iteration = click.prompt('Enter iteration', default='0')
        salt = '|'.join([domain, username, iteration])
        if click.confirm('Store "{}" as "{}"'.format(salt, label), abort=True):
            pts.store_generatable(label, salt)
    pts.save(PATH)
    click.echo('Secret stored!')

    if not encrypt and click.confirm('\nRetrieve secret?'):
        if not master_password:
            master_password = get_master_password(pts)

        secret = pts.get(label, master_password)
        if clipboard:
            to_clipboard(secret, timeout=10)
            click.echo('Secret copied to clipboard.')
        else:
            click.echo(secret)


@cli.command('get')
@click.argument('label', required=False)
@click.option('--salt', '-s',
              help='Run the secret generation algorithm on the given description.')
@click.option('--clipboard/--no-clipboard', default=True,
              help='Whether to copy password to clipboard or print it out (default: clipboard).')
@click.pass_context
def pts_get(ctx, label, salt, clipboard):
    """
    Retrieve secret.

    LABEL is the unique label of the secret.
    """
    pts = ctx.obj

    if salt:
        master_key = pts.master_key(get_master_password(pts))
        secret = generate(salt, master_key)
    else:
        if not label:
            label = click.prompt('Enter label of secret to retrieve')

        if pts.exists(label):
            master_password = get_master_password(pts)
            secret = pts.get(label, master_password)
        else:
            click.echo('Label "{}" does not exist.'.format(label))
            raise click.Abort()

    if clipboard:
        to_clipboard(secret, timeout=10)
        click.echo('Secret copied to clipboard.')
    else:
        click.echo(secret)


@cli.command('ls')
@click.option('--type', '-t', type=click.Choice(['encrypted', 'generatable']))
@click.option('--verbose', '-v', count=True, help='More information.')
@click.option('--quiet', '-q', is_flag=True, help='Do not print anything if no secrets.')
@click.pass_context
def pts_list(ctx, type, verbose, quiet):
    """
    List the secrets.
    """
    pts = ctx.obj

    if len(pts.labels) == 0:
        if not quiet:
            click.echo('No stored secrets.')
        return

    col = max(len(label) for label in pts.labels) + 4

    for label in sorted(pts.labels):
        if not type or type == pts.labels[label]['type']:
            if verbose > 1 and label in pts.generatable:
                click.echo('{:<{col}}{:<{col_}}{}'.format(
                    label,
                    'type: ' + pts.labels[label]['type'],
                    'salt: ' + pts.generatable[label],
                    col=col,
                    col_=20
                ))
            elif verbose > 0:
                click.echo('{:<{col}}{}'.format(
                    label,
                    'type: ' + pts.labels[label]['type'],
                    col=col
                ))
            else:
                click.echo(label)


@cli.command('rm')
@click.argument('label', required=False)
@click.pass_context
def pts_remove(ctx, label):
    """
    Remove secret.

    LABEL is the unique label of the secret.
    """
    pts = ctx.obj

    if not label:
        label = click.prompt('Enter label of secret to remove')

    if not pts.exists(label):
        click.echo('Label "{}" does not exist.'.format(label))
        raise click.Abort()

    click.confirm('Are you sure you want to remove "{}"?'.format(label), abort=True)

    info = pts.labels[label]

    if info['type'] == 'generatable':
        pts.remove_generatable(label)
    elif info['type'] == 'encrypted':
        master_password = get_master_password(pts)
        pts.remove_encrypted(label, master_password)

    pts.save(PATH)
    click.echo('Successfully removed "{}".'.format(label))


@cli.command('mv')
@click.argument('label')
@click.argument('new-label')
@click.pass_context
def pts_move(ctx, label, new_label):
    """
    Rename secret.

    LABEL is the unique name of the secret.
    NEW-LABEL is a new unique name for the secret..
    """
    pts = ctx.obj

    if not pts.exists(label):
        click.echo('Label "{}" does not exist.'.format(label))
        raise click.Abort()

    if pts.exists(new_label):
        click.echo('New label already exists.'.format(new_label))
        raise click.Abort()

    info = pts.labels[label]

    if info['type'] == 'generatable':
        pts.rename_generatable(label, new_label)
    elif info['type'] == 'encrypted':
        master_password = get_master_password(pts)
        pts.rename_encrypted(label, new_label, master_password)

    pts.save(PATH)
    click.echo('Successfully renamed "{}" to "{}".'.format(label, new_label))


if __name__ == '__main__':
    cli()
