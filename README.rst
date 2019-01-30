PassTheSalt
=============

.. image:: https://img.shields.io/pypi/v/passthesalt.svg?style=flat-square&colorB=4c1
    :target: https://pypi.org/project/passthesalt/
    :alt: PyPI Version

.. image:: https://img.shields.io/travis/rossmacarthur/passthesalt/master.svg?style=flat-square
    :target: https://travis-ci.org/rossmacarthur/passthesalt
    :alt: Build Status

.. image:: https://img.shields.io/codecov/c/github/rossmacarthur/passthesalt.svg?style=flat-square
    :target: https://codecov.io/gh/rossmacarthur/passthesalt
    :alt: Code Coverage

A command line application for deterministic password generation and password
storage.

Getting started
---------------

Install it using

::

    pip install passthesalt

and start storing secrets with

::

    pts add

How does it work?
-----------------

Secrets are generated on the fly using the same secure algorithm each time which
uses a *master password* and a *description* of the password. Only the
description of the secret is stored. This means the secrets are not stored
anywhere.

The generation algorithm is PBKDF2 using 2048 iterations of HMAC-SHA-256,
applied to (*full name* + *master password*) as the key and the *description* as
the salt.

Since sometimes you cannot choose your passwords the application also has
provision to securely encrypt secrets with the master password.

Usage
-----

The command line interface has the following commands

::

    add      Add a secret.
    encrypt  Encrypt a secret.
    get      Retrieve a secret.
    ls       List the secrets.
    mv       Relabel a secret.
    pull     Retrieve a remote store.
    push     Update the remote store.
    rm       Remove a secret.

All commands and options are documented in the cli. You can use the
:code:`--help` option with any command.

License
-------

This project is licensed under the MIT License. See the `LICENSE`_ file.

.. _LICENSE: LICENSE
