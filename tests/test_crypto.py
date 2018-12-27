from binascii import hexlify

from passthesalt.crypto import (
    decrypt, encrypt, generate, generate_key, passlify,
    passlify_legacy, pbkdf2_hash, pbkdf2_hash_bytes
)


def test_pbkdf2_hash_bytes():
    expected = (
        b'#\x1a\xfb}\xcd.\x86\x0c\xfdX\xab\x137+\xd1,'
        b'\x920v\xc3Y\x8a\x12\x19`2\x0fo\xec\x8aV\x98'
    )
    assert pbkdf2_hash_bytes('password', b'salt', iterations=1024, length=32) == expected


def test_pbkdf2_hash_own_salt():
    salt = hexlify(b'salt')
    expected = (salt, '231afb7dcd2e860cfd58ab13372bd12c923076c3')
    assert pbkdf2_hash('password', salt=salt, iterations=1024) == expected


def test_pbkdf2_hash_gen_salt():
    password = 'password'
    salt, hash = pbkdf2_hash(password)
    assert pbkdf2_hash(password, salt=salt)[1] == hash


def test_generate_key():
    assert generate_key('password') == b'XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg='


def test_encrypt_and_decrypt():
    master_key = 'password'

    for d in ({}, {'b': 'herp', 'a': 'derp'}, {'a': 5}):
        encrypted = encrypt(d, master_key)
        assert decrypt(encrypted, master_key) == d


def test_passlify_legacy():
    b = b'\x00'
    assert passlify_legacy(b) == 'b'

    b = b'\x35\x00\x26\x48'
    assert passlify_legacy(b) == 'aM-1'


def test_passlify():
    b = b'\x00'
    assert passlify(b) == 'B'

    b = b'\x00\x00\x00\x00'
    assert passlify(b) == 'Ty_7'


def test_generate():
    # these values are taken from PassTheSalt v2.2.1
    assert generate('salt', 'John Smith|password') == 'wDG4-5D$aexGL+gE*8HQ'
    assert generate('salt2', 'John Smith|password') == 'oitKf=l2ziz9*6MH%e@$'
    assert generate('salt', 'John Smith|password', version=1) == 'wDG4-5D$aexGL+gE*8HQ'
    assert generate('salt2', 'John Smith|password', version=1) == 'oitKf=l2ziz9*6MH%e@$'
