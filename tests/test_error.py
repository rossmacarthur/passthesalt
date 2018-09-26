from passthesalt.error import Error


def test_errors():
    e = Error('msg')
    assert e.message == 'msg'
    assert str(e) == 'msg'
