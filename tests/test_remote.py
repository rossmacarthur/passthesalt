import datetime
import json
from unittest.mock import Mock, patch

import requests
import requests.exceptions
from pytest import raises

from passthesalt.core import PassTheSalt
from passthesalt.exceptions import (
    ConflictingTimestamps, RemoteError, UnauthorizedAccess, UnexpectedStatusCode
)
from passthesalt.remote import Remote, Stow


class TestRemote:

    def test_with_auth(self):

        def get_auth(remote):
            return ('name', 'password')

        remote = Remote(location='https://api.store.com').with_auth(get_auth)

        assert remote._auth == get_auth
        assert remote.auth == ('name', 'password')
        assert remote._auth == ('name', 'password')

    def test_validate_response(self):
        remote = Remote(location='https://api.store.com')
        response = Mock(**{
            'status_code': 200,
            'raise_for_status.return_value': None
        })
        remote.validate_response(response)

        with raises(UnexpectedStatusCode) as e:
            response = Mock(**{
                'status_code': 400,
                'raise_for_status.side_effect': requests.exceptions.HTTPError
            })
            remote.validate_response(response)
            assert e.code == 400

    def test_request(self):
        remote = Remote(location='https://api.store.com')

        with patch('passthesalt.remote.requests.request') as mock_request:
            resp = Mock(**{
                'status_code': 200,
                'json.return_value': {'message': 'result'}
            })
            mock_request.return_value = resp
            assert remote.request('GET', remote.location) == resp

            resp = Mock(**{
                'status_code': 500,
                'raise_for_status.side_effect': requests.exceptions.HTTPError,
                'json.return_value': {'message': 'result'}
            })
            mock_request.return_value = resp
            with raises(RemoteError):
                remote.request('GET', remote.location)

            resp = Mock(**{
                'status_code': 200,
                'json.side_effect': json.decoder.JSONDecodeError('msg', 'doc', 0)
            })
            mock_request.return_value = resp
            assert remote.request('GET', remote.location) == resp

            mock_request.status_code = 200
            mock_request.side_effect = requests.exceptions.RequestException
            with raises(RemoteError):
                remote.request('GET', remote.location)

    def test_get(self):
        remote = Remote(location='https://api.store.com').with_auth(('name', 'password'))

        with patch('passthesalt.remote.Remote.request') as mock_request:
            mock_request.return_value = 'eyJtb2RpZmllZCI6ICIyMDE4LTEyLTI1IDAwOjAwOjAwIn0='
            expected = PassTheSalt(
                modified=datetime.datetime(year=2018, month=12, day=25)
            )
            assert remote.get() == expected

    def test_put(self):
        remote = Remote(location='https://api.store.com').with_auth(('name', 'password'))

        with patch('passthesalt.remote.Remote.request') as mock_request:
            pts = PassTheSalt(
                modified=datetime.datetime(year=2018, month=12, day=25)
            )
            expected = (
                'eyJtb2RpZmllZCI6ICIyMDE4LTEyLTI1IiwgImNvbmZpZyI6IH'
                't9LCAic2VjcmV0cyI6IHt9LCAidmVyc2lvbiI6ICIzLjAuMCJ9'
            )
            assert remote.put(pts) == mock_request.return_value
            assert mock_request.call_args[1]['data'] == expected


class TestStow:

    def test___init__(self):
        remote = Stow(
            location='https://api.store.com',
            token_location='https://api.store.com/token'
        )
        assert remote.location == 'https://api.store.com'
        assert remote.token_location == 'https://api.store.com/token'
        assert remote.token is None

    def test_validate_response(self):
        remote = Stow(
            location='https://api.store.com',
            token_location='https://api.store.com/token'
        )
        response = Mock(**{
            'status_code': 200,
            'json.return_value': {'message': 'nuff said'},
            'raise_for_status.return_value': None
        })
        remote.validate_response(response)

        with raises(UnexpectedStatusCode) as e:
            response = Mock(**{
                'status_code': 400,
                'json.return_value': {'message': 'nuff said'},
                'raise_for_status.side_effect': requests.exceptions.HTTPError
            })
            remote.validate_response(response)
            assert e.code == 400

        with raises(UnauthorizedAccess) as e:
            response.status_code = 401
            remote.validate_response(response)
            assert e.code == 401
            assert e.message == 'nuff said'

        with raises(ConflictingTimestamps) as e:
            response.status_code = 409
            remote.validate_response(response)
            assert e.code == 409
            assert e.message == 'nuff said'

        with raises(UnexpectedStatusCode) as e:
            response = Mock(**{
                'status_code': 500,
                'json.side_effect': json.decoder.JSONDecodeError('msg', 'doc', 0),
                'raise_for_status.side_effect': requests.exceptions.HTTPError
            })
            remote.validate_response(response)
            assert e.code == 500
            assert e.message is None

    def test_renew(self):
        remote = Stow(
            location='https://api.store.com',
            token_location='https://api.store.com/token'
        ).with_auth(('name', 'password'))
        assert remote.token is None

        with patch('passthesalt.remote.requests.request') as mock_request:
            mock_request.return_value = Mock(**{
                'status_code': 200,
                'json.return_value': {'token': 'thetoken'}
            })
            assert remote.renew() is None
            assert remote.token == 'thetoken'

    def test_handle_renew(self):
        remote = Stow(
            location='https://api.store.com',
            token_location='https://api.store.com/token'
        ).with_auth(('name', 'password'))

        with patch('passthesalt.remote.requests.request') as mock_request:
            mock_request.return_value = Mock(**{
                'status_code': 200,
                'json.return_value': {'token': 'thetoken'}
            })

            decorated_function = remote.handle_renew(
                Mock(side_effect=[UnauthorizedAccess('msg'), 1])
            )
            assert decorated_function() == 1

            decorated_function = remote.handle_renew(
                Mock(side_effect=[UnexpectedStatusCode('msg', 500), 1])
            )
            with raises(UnexpectedStatusCode):
                decorated_function()

    def test_get(self):
        remote = Stow(
            location='https://api.store.com',
            token_location='https://api.store.com/token'
        ).with_auth(('name', 'password'))
        remote.token = 'thetoken'

        with patch('passthesalt.remote.Stow.request') as mock_request:
            mock_request.return_value = Mock(**{
                'status_code': 200,
                'json.return_value': {'value': 'eyJtb2RpZmllZCI6ICIyMDE4LTEyLTI1IDAwOjAwOjAwIn0='}
            })
            expected = PassTheSalt(
                modified=datetime.datetime(year=2018, month=12, day=25)
            )
            assert remote.get() == expected
            assert mock_request.call_args[1]['auth'] == ('thetoken', 'unused')

    def test_put(self):
        remote = Stow(
            location='https://api.store.com',
            token_location='https://api.store.com/token'
        )
        remote.token = 'thetoken'

        with patch('passthesalt.remote.Stow.request') as mock_request:
            mock_request.return_value = Mock(**{
                'status_code': 200,
                'json.return_value': {'message': 'success'}
            })

            pts = PassTheSalt()
            assert remote.put(pts) == 'success'
            assert mock_request.call_args[1]['auth'] == ('thetoken', 'unused')

            mock_request.return_value = Mock(**{
                'status_code': 200,
                'json.side_effect': json.decoder.JSONDecodeError('msg', 'doc', 0),
            })
            pts = PassTheSalt()
            assert remote.put(pts) is None
