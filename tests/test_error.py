from passthesalt.error import ConflictingTimestamps, PassTheSaltError, UnauthorizedAccess


def test_errors():
    e = PassTheSaltError('msg')
    assert e.message == 'msg'
    assert str(e) == 'msg'
    assert repr(e) == "passthesalt.error.PassTheSaltError('msg')"

    e = UnauthorizedAccess('msg')
    assert e.message == 'msg'
    assert str(e) == 'msg'
    assert repr(e) == "passthesalt.error.UnauthorizedAccess('msg', code=401)"
    assert e.code == 401

    e = ConflictingTimestamps('msg')
    assert e.message == 'msg'
    assert str(e) == 'msg'
    assert repr(e) == "passthesalt.error.ConflictingTimestamps('msg', code=409)"
    assert e.code == 409
