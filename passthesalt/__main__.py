from __future__ import absolute_import, division, print_function, unicode_literals
import click
import copy
import os
import re
from passthesalt import PassTheSalt, Remote, UnauthorizedAccess, ConflictingTimestamps, \
                        to_clipboard, generate, __version__

click.disable_unicode_literals_warning = True

DEFAULT_PATH = os.path.expanduser('~/.passthesalt')
DEFAULT_REMOTE = os.path.expanduser('~/.passthesalt.remote')


def dict_diff(d1, d2):
    if not isinstance(d1, dict):
        return d1

    diff = dict()

    for key in d1:
        if key not in d2:
            diff[key] = d1[key]
        elif d1[key] != d2[key]:
            diff[key] = dict_diff(d1[key], d2[key])

    return diff


def pts_diff_(pts1, pts2):
    return PassTheSalt().loads(
        dict_diff(copy.deepcopy(pts1.to_dict()), copy.deepcopy(pts2.to_dict())))


def pts_list_(pts, label=None, type=None, verbose=0, quiet=False):
    subset = [l for l in pts.labels if not label or l.lower().startswith(label.lower())]

    if len(subset) == 0:
        if not quiet:
            click.echo('No stored secrets.')
        return

    col = max(len(l) for l in subset) + 4

    for label in sorted(subset):
        if not type or type == pts.labels[label]['type']:
            if verbose > 1 and label in pts.generatable:
                click.echo('{:<{col}}{:<{col_}}{}'.format(
                    label,
                    'type: ' + pts.labels[label].get('type', 'generatable'),
                    'salt: ' + pts.generatable[label],
                    col=col,
                    col_=20
                ))
            elif verbose > 0:
                click.echo('{:<{col}}{}'.format(
                    label,
                    'type: ' + pts.labels[label].get('type', 'encrypted'),
                    col=col
                ))
            else:
                click.echo(label)


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


def renew_remote_token(remote, remote_path):
    click.echo('Unauthorized access. Need to renew token:')
    name = click.prompt('Enter name')
    password = click.prompt('Enter password', hide_input=True)
    remote.renew_token(name, password)
    remote.save(remote_path)


def get_remote(remote, remote_path):
    for _ in range(2):
        try:
            return remote.get()
        except UnauthorizedAccess:
            renew_remote_token(remote, remote_path)


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(__version__, '-v', '--version', prog_name='passthesalt',
                      message='%(prog)s %(version)s')
@click.option('--path', '-p', type=click.Path(), default=DEFAULT_PATH,
              help='The store path.')
@click.option('--remote-path', '-r', type=click.Path(), default=DEFAULT_REMOTE,
              help='The remote config path.')
@click.pass_context
def cli(ctx, path, remote_path):
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
    remote = Remote()

    if os.path.isfile(path):
        pts.load(path)
    elif ctx.invoked_subcommand == 'pull':
        pass
    else:
        click.echo('Initializing Pass the Salt ...')
        owner = click.prompt('Please enter your name')

        if click.confirm('Use master password validation?'):
            master_password = click.prompt('Please enter the master password',
                                           confirmation_prompt=True, hide_input=True)
            pts.initialize(owner, master_password)
        else:
            pts.initialize(owner)

        pts.save(path)
        click.echo('Successfully initialized Pass The Salt!\n')

    if os.path.isfile(remote_path):
        remote = remote.load(remote_path)
    elif ctx.invoked_subcommand in ('push', 'pull'):
        click.echo('Initializing remote ...')

        url = click.prompt('Enter GET and PUT url')
        token_url = click.prompt('Enter token renewal url')
        remote.initialize(url, token_url)

        remote.save(remote_path)
        click.echo('Successfully initialized remote config.\n')

    ctx.obj = {
        'pts': pts,
        'remote': remote,
        'path': path,
        'remote_path': remote_path
    }


@cli.command('add')
@click.argument('label', required=False)
@click.option('--encrypt', '-e', is_flag=True, help='Store and encrypt a secret.')
@click.option('--clipboard/--no-clipboard', default=True,
              help='Whether to copy secret to clipboard or print it out (default: clipboard).')
@click.pass_obj
def pts_add(obj, label, encrypt, clipboard):
    """
    Store secret.

    LABEL is the unique label for the secret.
    """
    pts = obj['pts']
    path = obj['path']

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
    pts.save(path)
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
@click.pass_obj
def pts_get(obj, label, salt, clipboard):
    """
    Retrieve secret.

    LABEL is the unique label of the secret.
    """
    pts = obj['pts']

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
@click.argument('label', required=False)
@click.option('--type', '-t', type=click.Choice(['encrypted', 'generatable']))
@click.option('--verbose', '-v', count=True, help='More information.')
@click.option('--quiet', '-q', is_flag=True, help='Do not print anything if no secrets.')
@click.pass_obj
def pts_list(obj, label, type, verbose, quiet):
    """
    List the secrets.
    """
    pts = obj['pts']
    pts_list_(pts, label, type, verbose, quiet)


@cli.command('rm')
@click.argument('label', required=False)
@click.pass_obj
def pts_remove(obj, label):
    """
    Remove secret.

    LABEL is the unique label of the secret.
    """
    pts = obj['pts']
    path = obj['path']

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

    pts.save(path)
    click.echo('Successfully removed "{}".'.format(label))


@cli.command('mv')
@click.argument('label')
@click.argument('new-label')
@click.pass_obj
def pts_move(obj, label, new_label):
    """
    Rename secret.

    LABEL is the unique name of the secret.
    NEW-LABEL is a new unique name for the secret..
    """
    pts = obj['pts']
    path = obj['path']

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

    pts.save(path)
    click.echo('Successfully renamed "{}" to "{}".'.format(label, new_label))


@cli.command('push')
@click.option('--force', '-f', is_flag=True, help='Ignore timestamp conflicts.')
@click.pass_obj
def pts_push(obj, force):
    """
    Update remote store with local store.
    """
    pts = obj['pts']
    remote = obj['remote']
    remote_path = obj['remote_path']

    for _ in range(2):
        try:
            remote.put(pts, force=force)
            break
        except UnauthorizedAccess:
            renew_remote_token(remote, remote_path)
        except ConflictingTimestamps:
            click.echo('Timestamp conflict. The server has a newer version of the store. '
                       'Use --force to override.')
            raise click.Abort()

    remote.touch()
    remote.save(remote_path)
    click.echo('Successfully pushed to remote store.')


@cli.command('pull')
@click.option('--force', '-f', is_flag=True, help='Ignore timestamp conflicts.')
@click.pass_obj
def pts_pull(obj, force):
    """
    Update local store with remote store.
    """
    pts = obj['pts']
    remote = obj['remote']
    path = obj['path']
    remote_path = obj['remote_path']

    remote_pts, modified = get_remote(remote, remote_path)

    if not pts or force or (hasattr(pts, 'modified') and modified > pts.modified):
        remote_pts.save(path)
        click.echo('Successfully pulled remote store.')
    else:
        click.echo('Timestamp conflict. The local version is newer than the remote.')
        raise click.Abort()


@cli.command('diff')
@click.option('--filename', '-f', type=click.Path(exists=True, dir_okay=False))
@click.option('--type', '-t', type=click.Choice(['encrypted', 'generatable']))
@click.option('--verbose', '-v', count=True, help='More information.')
@click.pass_obj
def pts_diff(obj, filename, type, verbose):
    """
    Compare two stores.
    """
    pts = obj['pts']
    remote = obj['remote']
    remote_path = obj['remote_path']

    if filename:
        other_pts = PassTheSalt().load(filename)
    else:
        other_pts, _ = get_remote(remote, remote_path)

    other_has = pts_diff_(other_pts, pts)
    if other_has.labels:
        click.echo('The {} store has the following secrets:'.format(filename or 'remote'))
        pts_list_(other_has, type=type, verbose=verbose)

    local_has = pts_diff_(pts, other_pts)
    if local_has.labels:
        click.echo('The local store has the following secrets:')
        pts_list_(local_has, type=type, verbose=verbose)

    if other_has.labels or local_has.labels:
        exit(1)


if __name__ == '__main__':
    cli()
