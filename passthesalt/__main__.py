import click
import os
import re
from passthesalt import PassTheSalt, to_clipboard, generate, __version__


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
@click.option('--encrypt', '-e', is_flag=True, help='Store and encrypt a password.')
@click.pass_context
def pts_add(ctx, label, encrypt):
    """
    Store a password.

    LABEL is the unique label for the password.
    """
    pts = ctx.obj

    if not label:
        label = click.prompt('Enter label for new password')

    if pts.exists(label):
        click.echo('Label "{}" already exists.'.format(label))
    else:
        if encrypt:
            secret = click.prompt('Enter password to store', confirmation_prompt=True, hide_input=True)
            master_password = get_master_password(pts)
            pts.store_encrypted(label, secret, master_password)
        else:
            domain = click.prompt('Enter domain name', type=URL)
            username = click.prompt('Enter username')
            iteration = click.prompt('Enter iteration', default='0')
            salt = '|'.join([domain, username, iteration])
            if click.confirm('Store "{}" as "{}"'.format(salt, label)):
                pts.store_generatable(label, salt)

        pts.save(PATH)
        click.echo('Password stored!')


@cli.command('get')
@click.argument('label', required=False)
@click.option('--salt', '-s',
              help='Run the password generation algorithm on the given description.')
@click.option('--clipboard/--no-clipboard', default=True,
              help='Whether to copy password to clipboard or print it out (default: clipboard).')
@click.pass_context
def pts_get(ctx, label, salt, clipboard):
    """
    Retrieve a password.

    LABEL is the unique label of the password.
    """
    pts = ctx.obj

    if salt:
        master_key = pts.master_key(get_master_password(pts))
        password = generate(salt, master_key)
    else:
        if not label:
            label = click.prompt('Enter label of password to retrieve')

        if pts.exists(label):
            master_password = get_master_password(pts)
            password = pts.get(label, master_password)
        else:
            click.echo('Label "{}" does not exist.'.format(label))
            raise click.Abort()

    if clipboard:
        to_clipboard(password, timeout=10)
        click.echo('Password copied to clipboard.')
    else:
        click.echo(password)


@cli.command('ls')
@click.option('--verbose', '-v', count=True, help='More information.')
@click.option('--quiet', '-q', is_flag=True, help='Do not print anything if no passwords.')
@click.pass_context
def pts_list(ctx, verbose, quiet):
    """
    List the passwords.
    """
    pts = ctx.obj

    if len(pts.labels) == 0:
        if not quiet:
            click.echo('No stored passwords.')
    else:
        col = max(len(label) for label in pts.labels) + 4

        for label in sorted(pts.labels):
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
def pts_rm(ctx, label):
    """
    Remove a password.

    LABEL is the unique label of the password.
    """
    pts = ctx.obj

    if not label:
        label = click.prompt('Enter label of password to remove')

    if pts.exists(label):
        click.confirm('Are you sure you want to remove "{}"?'.format(label), abort=True)

        info = pts.labels[label]

        if info['type'] == 'generatable':
            pts.remove_generatable(label)
        elif info['type'] == 'encrypted':
            master_password = get_master_password(pts)
            pts.remove_encrypted(label, master_password)

        pts.save(PATH)
        click.echo('Successfully removed "{}"'.format(label))
    else:
        click.echo('Label "{}" does not exist.'.format(label))
        raise click.Abort()


if __name__ == '__main__':
    cli()
