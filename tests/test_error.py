from passthesalt import ConflictingTimestamps, Error, UnauthorizedAccess


def test_errors():
    e = Error('msg')
    assert e.message == 'msg'
    assert str(e) == 'msg'

    e = UnauthorizedAccess('msg')
    assert e.message == 'msg'
    assert str(e) == 'msg'
    assert e.code == 401

    e = ConflictingTimestamps('msg')
    assert e.message == 'msg'
    assert str(e) == 'msg'
    assert e.code == 409
