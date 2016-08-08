try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
try:
    from urllib.parse import parse_qs, urlsplit
except ImportError:
    from urlparse import parse_qs, urlsplit
import uuid

from django.contrib.auth.models import AnonymousUser
from django.core.management import call_command
from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase
from jwkest.jwt import JWT

from oidc_provider.models import *
from oidc_provider.tests.app.utils import *
from oidc_provider.views import *


class ImplicitFlowTestCase(TestCase):
    """
    Test cases for Authorization Implicit Flow.
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='id_token token')
        self.client_public = create_fake_client(response_type='id_token token', is_public=True)
        self.client_no_access = create_fake_client(response_type='id_token')
        self.client_public_no_access = create_fake_client(response_type='id_token', is_public=True)
        self.state = uuid.uuid4().hex
        self.nonce = uuid.uuid4().hex

    def _auth_request(self, method, data={}, is_user_authenticated=False):
        url = reverse('oidc_provider:authorize')

        if method.lower() == 'get':
            query_str = urlencode(data).replace('+', '%20')
            if query_str:
                url += '?' + query_str
            request = self.factory.get(url)
        elif method.lower() == 'post':
            request = self.factory.post(url, data=data)
        else:
            raise Exception('Method unsupported for an Authorization Request.')

        # Simulate that the user is logged.
        request.user = self.user if is_user_authenticated else AnonymousUser()

        response = AuthorizeView.as_view()(request)

        return response

    def test_missing_nonce(self):
        """
        The `nonce` parameter is REQUIRED if you use the Implicit Flow.
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': self.client.response_type,
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data, is_user_authenticated=True)

        self.assertEqual('#error=invalid_request' in response['Location'], True)

    def test_id_token_token_response(self):
        """
        Implicit client requesting `id_token token` receives both id token
        and access token as the result of the authorization request.
        """
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': self.client.response_type,
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

        # same for public client
        data['client_id'] = self.client_public.client_id,
        data['redirect_uri'] = self.client_public.default_redirect_uri,
        data['response_type'] = self.client_public.response_type,

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

    def test_id_token_response(self):
        """
        Implicit client requesting `id_token` receives
        only an id token as the result of the authorization request.
        """
        data = {
            'client_id': self.client_no_access.client_id,
            'redirect_uri': self.client_no_access.default_redirect_uri,
            'response_type': self.client_no_access.response_type,
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertNotIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

        # same for public client
        data['client_id'] = self.client_public_no_access.client_id,
        data['redirect_uri'] = self.client_public_no_access.default_redirect_uri,
        data['response_type'] = self.client_public_no_access.response_type,

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertNotIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

    def test_id_token_token_at_hash(self):
        """
        Implicit client requesting `id_token token` receives
        `at_hash` in `id_token`.
        """
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': self.client.response_type,
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('id_token', response['Location'])

        # obtain `id_token` portion of Location
        components = urlsplit(response['Location'])
        fragment = parse_qs(components[4])
        id_token = JWT().unpack(fragment["id_token"][0].encode('utf-8')).payload()

        self.assertIn('at_hash', id_token)

    def test_id_token_at_hash(self):
        """
        Implicit client requesting `id_token` should not receive
        `at_hash` in `id_token`.
        """
        data = {
            'client_id': self.client_no_access.client_id,
            'redirect_uri': self.client_no_access.default_redirect_uri,
            'response_type': self.client_no_access.response_type,
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('id_token', response['Location'])

        # obtain `id_token` portion of Location
        components = urlsplit(response['Location'])
        fragment = parse_qs(components[4])
        id_token = JWT().unpack(fragment["id_token"][0].encode('utf-8')).payload()

        self.assertNotIn('at_hash', id_token)
