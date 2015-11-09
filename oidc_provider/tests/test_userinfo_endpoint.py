from datetime import timedelta
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase
from django.utils import timezone

from oidc_provider.lib.utils.token import *
from oidc_provider.models import *
from oidc_provider.tests.app.utils import *
from oidc_provider.views import userinfo


class UserInfoTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')

    def _create_token(self, extra_scope=[]):
        """
        Generate a valid token.
        """
        id_token_dic = create_id_token(self.user,
                                       self.client.client_id, FAKE_NONCE)

        token = create_token(
            user=self.user,
            client=self.client,
            id_token_dic=id_token_dic,
            scope=['openid', 'email'] + extra_scope)
        token.save()

        return token

    def _post_request(self, access_token):
        """
        Makes a request to the userinfo endpoint by sending the
        `post_data` parameters using the 'multipart/form-data'
        format.
        """
        url = reverse('oidc_provider:userinfo')

        request = self.factory.post(url,
            data={},
            content_type='multipart/form-data')

        request.META['HTTP_AUTHORIZATION'] = 'Bearer ' + access_token

        response = userinfo(request)

        return response

    def test_response_with_valid_token(self):
        token = self._create_token()

        # Test a valid request to the userinfo endpoint.
        response = self._post_request(token.access_token)

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
        self.assertEqual('given_name' in response_dic, True,
            msg='"given_name" claim should be in response.')
        self.assertEqual('profile' in response_dic, False,
            msg='"profile" claim should not be in response.')

        # Now adding `address` scope.
        token = self._create_token(extra_scope=['profile', 'address'])
        response = self._post_request(token.access_token)
        response_dic = json.loads(response.content.decode('utf-8'))

        self.assertEqual('address' in response_dic, True,
            msg='"address" claim should be in response.')
        self.assertEqual('country' in response_dic['address'], True,
            msg='"country" claim should be in response.')
