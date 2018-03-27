Pass the Salt
=============

A command line application for deterministic password generation and password storage.

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

Secrets are generated on the fly using the same secure algorithm each time which uses a *master password* and a *description* of the password. Only the description of the secret is stored. This means the secrets are not stored anywhere.

The generation algorithm is PBKDF2 using 2048 iterations of HMAC-SHA-256, applied to (*full name* + *master password*) as the key and the *description* as the salt.

Since sometimes you cannot choose your passwords the application also has provision to securely AES (CFB) encrypt secrets with the master password.

Usage
-----

The cli has the following commands

::

    add   Store secret.
    diff  Compare two stores.
    get   Retrieve secret.
    ls    List the secrets.
    mv    Rename secret.
    pull  Update local store with remote store.
    push  Update remote store with local store.
    rm    Remove secret.

All commands and options are documented in the cli. You can use the :code:`--help` option with any command.

License
-------

This project is licensed under the MIT License. See the `LICENSE.txt`_ file.

.. _LICENSE.txt: LICENSE.txt
