# PassTheSalt

[![PyPI](https://img.shields.io/pypi/v/passthesalt)](https://pypi.org/project/passthesalt/)
![PyPI: supported Python](https://img.shields.io/pypi/pyversions/passthesalt)
[![Build status](https://img.shields.io/github/workflow/status/rossmacarthur/passthesalt/build)](https://github.com/rossmacarthur/passthesalt/actions?query=workflow%3Abuild)
[![Code coverage](https://img.shields.io/codecov/c/github/rossmacarthur/passthesalt/master.svg)](https://codecov.io/gh/rossmacarthur/passthesalt)
[![Code style](https://img.shields.io/badge/code%20style-black-101010.svg)](https://github.com/psf/black)

A command line application for deterministic password generation and password
storage.

## Getting started

Install it using

```sh
pip install passthesalt
```

and start storing secrets with

```sh
pts add
```

## How does it work?

Secrets are generated on the fly using the same secure algorithm each time which
uses a *master password* and a *description* of the password. Only the
description of the secret is stored. This means the secrets are not stored
anywhere.

The generation algorithm is PBKDF2 using 2048 iterations of HMAC-SHA-256,
applied to (*full name* + *master password*) as the key and the *description* as
the salt.

Since sometimes you cannot choose your passwords the application also has
provision to securely encrypt secrets with the master password.

## Usage


The command-line interface has the following commands

```
add      Add a secret.
diff     Compare two stores.
edit     Edit a secret.
encrypt  Encrypt a secret.
get      Retrieve a secret.
ls       List the secrets.
mv       Relabel a secret.
pull     Retrieve a remote store.
push     Update the remote store.
rm       Remove a secret.
```

All commands and options are documented in the cli. You can use the `--help`
option with any command.

## License

This project is licensed under the MIT license ([LICENSE](LICENSE) or
http://opensource.org/licenses/MIT).
