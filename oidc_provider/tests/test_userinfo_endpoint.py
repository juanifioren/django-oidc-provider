from datetime import timedelta

from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase
from django.utils import timezone

from oidc_provider.lib.utils.token import *
from oidc_provider.models import *
from oidc_provider.tests.utils import *
from oidc_provider.views import userinfo


class UserInfoTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')

    def _create_token(self):
        """
        Generate a valid token.
        """
        id_token_dic = create_id_token(self.user, self.client.client_id)

        token = create_token(
            user=self.user,
            client=self.client,
            id_token_dic=id_token_dic,
            scope=['openid', 'email'])
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