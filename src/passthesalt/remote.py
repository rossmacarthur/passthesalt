"""
Remote configuration for PassTheSalt.
"""

import json

import requests
from serde import fields

from passthesalt.core import PassTheSalt
from passthesalt.exceptions import (
    ConflictingTimestamps,
    RemoteError,
    UnauthorizedAccess,
    UnexpectedStatusCode,
)
from passthesalt.model import Model


class Remote(Model):
    """
    Configuration for a remote store.
    """

    location: fields.Url()

    def with_auth(self, auth):
        """
        Configure the Remote with authentication.

        Args:
            auth: the authentication for communicating with the remote store.
                This can be a callback for getting the authentication (for
                example through user input), or the actual authentication.
        """
        self._auth = auth
        return self

    @property
    def auth(self):
        """
        The configured authentication.

        Returns:
            the configured authentication.
        """
        if callable(self._auth):
            self._auth = self._auth(self)

        return self._auth

    @property
    def headers(self):
        """
        General headers to use when making requests to the remote server.

        Returns:
            dict: the headers.
        """
        return {}

    def validate_response(self, response):
        """
        Validate the given response.

        Args:
            response (Response): the requests response.

        Raises:
            UnexpectedStatusCode: for a bad response code.
        """
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise UnexpectedStatusCode(str(e) or repr(e), response.status_code)

    def request(self, verb, url, headers=None, auth=None, data=None):
        """
        Make a remote request to the given URL.

        Args:
            verb (str): the HTTP method like 'GET' or 'POST'.
            url (str): the URL to request.
            headers (dict): extra headers to use.
            auth (tuple): authentication to use.
            data (str): the payload.

        Raises:
            RemoteError: when a generic requests exception occurs.

        Returns:
            dict: the server response.
        """
        try:
            response = requests.request(
                verb, url, headers=headers, auth=auth, data=data
            )
        except requests.exceptions.RequestException as e:
            raise RemoteError(str(e) or repr(e))
        else:
            self.validate_response(response)
            return response

    def get(self):
        """
        Retrieve the Remote store.

        Returns:
            PassTheSalt: a PassTheSalt instance.
        """
        data = self.request('GET', self.location, headers=self.headers, auth=self.auth)
        return PassTheSalt.from_base64(data)

    def put(self, pts):
        """
        Upload the given PassTheSalt to the Remote store.

        Args:
            pts (PassTheSalt): a PassTheSalt instance.

        Returns:
            Response: the response from the server.
        """
        data = pts.to_base64()
        return self.request(
            'PUT', self.location, headers=self.headers, auth=self.auth, data=data
        )


class Stow(Remote):
    """
    Stow configuration for a remote store.

    See https://github.com/rossmacarthur/stow.
    """

    token: fields.Optional(fields.Str)
    token_location: fields.Url()

    @property
    def headers(self):
        """
        General headers to use when making requests to the remote server.

        Returns:
            dict: the headers.
        """
        return {'Content-Type': 'application/json'}

    def validate_response(self, response):
        """
        Validate the given response.

        Args:
            response (Response): the requests response.

        Raises:
            UnauthorizedAccess: when the response code is 401.
            ConflictingTimestamps: when the response code is 409.
        """
        try:
            message = response.json().get('message')
        except json.decoder.JSONDecodeError:
            message = None

        if response.status_code == 401:
            raise UnauthorizedAccess(message)
        elif response.status_code == 409:
            raise ConflictingTimestamps(message)

        super().validate_response(response)

    def renew(self):
        """
        Renew the internal token with the configured authentication.
        """
        data = self.request(
            'GET', self.token_location, headers=self.headers, auth=self.auth
        ).json()
        self.token = data['token']
        self.touch()

    def handle_renew(self, f):
        """
        Decorator to recall a function if the token needs to be renewed.

        If the given function raises UnauthorizedAccess then renew the token and
        recall the function.

        Args:
            f (callable): the function that accesses some secure resource.

        Returns:
            the result of the function.
        """

        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except UnauthorizedAccess:
                self.renew()
                return f(*args, **kwargs)

        return decorated_function

    def get(self):
        """
        Retrieve the Remote store.

        Returns:
            PassTheSalt: a PassTheSalt instance.
        """

        @self.handle_renew
        def get():
            return self.request(
                'GET', self.location, headers=self.headers, auth=(self.token, 'unused')
            ).json()

        return PassTheSalt.from_base64(get()['value'])

    def put(self, pts, force=False):
        """
        Upload the given PassTheSalt to the Remote store.

        Args:
            pts (PassTheSalt): a PassTheSalt instance.
            force (bool): whether to ignore any conflicts.

        Returns:
            dict: the message from the server.
        """

        @self.handle_renew
        def put(pts):
            payload = {'value': pts.to_base64()}

            if not force:
                payload['modified'] = pts.modified.isoformat()

            data = json.dumps(payload)
            return self.request(
                'PUT',
                self.location,
                headers=self.headers,
                auth=(self.token, 'unused'),
                data=data,
            )

        try:
            message = put(pts).json().get('message')
        except json.decoder.JSONDecodeError:
            message = None

        return message
