import json

from datetime import timedelta
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase
from django.utils import timezone

from oidc_provider.lib.utils.token import (
    create_id_token,
    create_token,
)
from oidc_provider.tests.app.utils import (
    create_fake_user,
    create_fake_client,
    FAKE_NONCE,
)
from oidc_provider.views import userinfo


class UserInfoTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')
        self.url = reverse('oidc_provider:userinfo')

    def _create_token(self, extra_scope=None):
        """
        Generate a valid token.
        """
        if extra_scope is None:
            extra_scope = []
        scope = ['openid', 'email'] + extra_scope

        token = create_token(
            user=self.user,
            client=self.client,
            scope=scope)

        id_token_dic = create_id_token(
            token=token,
            user=self.user,
            aud=self.client.client_id,
            nonce=FAKE_NONCE,
            scope=scope,
        )

        token.id_token = id_token_dic
        token.save()

        return token

    def _post_request(self, access_token, schema='Bearer'):
        """
        Makes a request to the userinfo endpoint by sending the
        `post_data` parameters using the 'multipart/form-data'
        format.
        """
        request = self.factory.post(self.url, data={}, content_type='multipart/form-data')

        request.META['HTTP_AUTHORIZATION'] = schema + ' ' + access_token

        response = userinfo(request)

        return response

    def test_response_with_valid_token(self):
        token = self._create_token()

        # Test a valid request to the userinfo endpoint.
        response = self._post_request(token.access_token)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(bool(response.content), True)

    def test_response_with_valid_token_lowercase_bearer(self):
        """
        Some clients expect to be able to pass the token_type value from the token endpoint
        ("bearer") back to the identity provider unchanged.
        """
        token = self._create_token()

        response = self._post_request(token.access_token, schema='bearer')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(bool(response.content), True)

    def test_response_with_expired_token(self):
        token = self._create_token()

        # Make token expired.
        token.expires_at = timezone.now() - timedelta(hours=1)
        token.save()

        response = self._post_request(token.access_token)

        self.assertEqual(response.status_code, 401)

        try:
            is_header_field_ok = 'invalid_token' in response['WWW-Authenticate']
        except KeyError:
            is_header_field_ok = False
        self.assertEqual(is_header_field_ok, True)

    def test_response_with_invalid_scope(self):
        token = self._create_token()

        token.scope = ['otherone']
        token.save()

        response = self._post_request(token.access_token)

        self.assertEqual(response.status_code, 403)

        try:
            is_header_field_ok = 'insufficient_scope' in response['WWW-Authenticate']
        except KeyError:
            is_header_field_ok = False
        self.assertEqual(is_header_field_ok, True)

    def test_accesstoken_query_string_parameter(self):
        """
        Make a GET request to the UserInfo Endpoint by sending access_token
        as query string parameter.
        """
        token = self._create_token()

        url = reverse('oidc_provider:userinfo') + '?' + urlencode({
            'access_token': token.access_token,
        })

        request = self.factory.get(url)
        response = userinfo(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(bool(response.content), True)

    def test_user_claims_in_response(self):
        token = self._create_token(extra_scope=['profile'])
        response = self._post_request(token.access_token)
        response_dic = json.loads(response.content.decode('utf-8'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(bool(response.content), True)
        self.assertIn('given_name', response_dic, msg='"given_name" claim should be in response.')
        self.assertNotIn('profile', response_dic, msg='"profile" claim should not be in response.')

        # Now adding `address` scope.
        token = self._create_token(extra_scope=['profile', 'address'])
        response = self._post_request(token.access_token)
        response_dic = json.loads(response.content.decode('utf-8'))

        self.assertIn('address', response_dic, msg='"address" claim should be in response.')
        self.assertIn(
            'country', response_dic['address'], msg='"country" claim should be in response.')

    def test_options_request_without_token(self):
        request = self.factory.options(self.url)
        request.META['HTTP_ORIGIN'] = "test.example.com"
        response = userinfo(request)

        expected_headers = {
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Origin": "test.example.com",
        }

        self.assertEqual(response.status_code, 200)
        for key, value in expected_headers.items():
            self.assertEqual(response[key], value)
