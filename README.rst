Pass the Salt
=============

Pass the Salt is a deterministic password generation and password storage system.

Install it using

::

    pip install passthesalt

and get started by running 

::
    
    pts add


How does it work?
-----------------

Passwords are generated on the fly using the same secure algorithm which uses a *master password* and a *description* of the password. Only the description of the password is stored.

If it is really needed it is also possible to AES (CFB) encrypt passwords with the master password.

What is the generation algorithm?
---------------------------------

PBKDF2 and 2048 iterations of HMAC-SHA-256 applied to (*full name* + *master password*) as the key and the *description* as the salt.
