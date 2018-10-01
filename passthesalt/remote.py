"""
Remote configuration for PassTheSalt.
"""

import json

import requests

from passthesalt.core import PassTheSalt
from passthesalt.error import (ConflictingTimestamps, RemoteError,
                               UnauthorizedAccess, UnexpectedStatusCode)
from passthesalt.schema import Function, Parameters, Schema


class Remote(Schema):
    """
    Configuration for a remote store.
    """

    class Meta:
        constructor = Function(args=Parameters(location=str))
        modified = True

    def __init__(self, location):
        """
        Create a new Remote.

        Args:
            location (Text): the URL location of the remote store.
        """
        super().__init__()
        self.location = location
        self._auth = None

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
            Dict[Text, Text]: the headers.
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
            raise UnexpectedStatusCode(str(e), response.status_code)

    def request(self, verb, url, headers=None, auth=None, data=None):
        """
        Make a remote request to the given URL.

        Args:
            verb (Text): the HTTP method like 'GET' or 'POST'.
            url (Text): the URL to request.
            headers (Dict): extra headers to use.
            auth (Tuple): authentication to use.
            data (Text): the payload.

        Raises:
            RemoteError: when a generic requests exception occurs.

        Returns:
            Dict: the server response.
        """
        try:
            response = requests.request(verb, url, headers=headers, auth=auth, data=data)
            self.validate_response(response)
            return response
        except requests.exceptions.RequestException as e:
            raise RemoteError(str(e))

    def get(self):
        """
        Retrieve the Remote store.

        Returns:
            PassTheSalt: a PassTheSalt instance.
        """
        data = self.request('GET', self.location, headers=self.headers, auth=self.auth)
        return PassTheSalt.decode(data)

    def put(self, pts):
        """
        Upload the given PassTheSalt to the Remote store.

        Args:
            pts (PassTheSalt): a PassTheSalt instance.

        Returns:
            Response: the response from the server.
        """
        data = pts.encode()
        return self.request('PUT', self.location, headers=self.headers, auth=self.auth, data=data)


class Stow(Remote):
    """
    Stow configuration for a remote store.

    See https://github.com/rossmacarthur/stow.
    """

    class Meta:
        constructor = Function(args=Parameters(('location', str), ('token_location', str)))
        attributes = Parameters(token=str)

    def __init__(self, location, token_location):
        """
        Create a new Remote.

        Args:
            location (Text): the URL of the remote store.
            token_location (Text): the URL to renew access to the remote store.
        """
        super().__init__(location)
        self.token_location = token_location
        self.token = None

    @property
    def headers(self):
        """
        General headers to use when making requests to the remote server.

        Returns:
            Dict[Text, Text]: the headers.
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
        data = self.request('GET', self.token_location,
                            headers=self.headers, auth=self.auth).json()
        self.token = data['token']
        self.touch()

    def handle_renew(self, func):
        """
        Decorator to recall a function if the token needs to be renewed.

        If the given function raises UnauthorizedAccess then renew the token and
        recall the function.

        Args:
            func (Callable): the function that accesses some secure resource.

        Returns:
            the result of the function.
        """
        def decorated_function(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except UnauthorizedAccess:
                self.renew()
                return func(*args, **kwargs)

        return decorated_function

    def get(self):
        """
        Retrieve the Remote store.

        Returns:
            PassTheSalt: a PassTheSalt instance.
        """
        @self.handle_renew
        def get():
            return self.request('GET', self.location, headers=self.headers,
                                auth=(self.token, 'unused')).json()

        return PassTheSalt.decode(get()['value'])

    def put(self, pts, force=False):
        """
        Upload the given PassTheSalt to the Remote store.

        Args:
            pts (PassTheSalt): a PassTheSalt instance.
            force (bool): whether to ignore any conflicts.

        Returns:
            Dict: the message from the server.
        """
        @self.handle_renew
        def put(pts):
            payload = {'value': pts.encode()}

            if not force:
                payload['modified'] = pts.modified.isoformat()

            data = json.dumps(payload)
            return self.request('PUT', self.location, headers=self.headers,
                                auth=(self.token, 'unused'), data=data)

        try:
            message = put(pts).json().get('message')
        except json.decoder.JSONDecodeError:
            message = None

        return message
