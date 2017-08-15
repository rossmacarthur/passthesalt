# Pass the Salt

Pass the Salt is a deterministic password generation and password storage system :key:.

### How does it work?

Passwords are generated on the fly using the same secure algorithm which uses a _master password_ and a _description_ of the password. Only the description of the password is stored.

If it is really needed it is also possible to AES (CFB) encrypt the passwords with the master password.

### What is the generation algorithm?

PBKDF2 and 2048 iterations of HMAC-SHA-256 applied to (_full name_ + _master password_) as the key and the _description_ as the salt.

### TODO

* Reduce dependencies (especially `click`).
* Get an external review of the security of this script and algorithm.
