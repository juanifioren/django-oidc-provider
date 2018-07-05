import time
import random

from mock import patch
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
from django.utils.encoding import force_text
from django.core.management import call_command
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse

from oidc_provider.tests.app.utils import (
    create_fake_user,
    create_fake_client,
    create_fake_token,
    FAKE_RANDOM_STRING)
from oidc_provider.lib.utils.token import create_id_token
from oidc_provider.views import TokenIntrospectionView


class IntrospectionTestCase(TestCase):

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.aud = 'testaudience'
        self.client = create_fake_client(response_type='id_token token')
        self.resource = create_fake_client(response_type='id_token token')
        self.resource.scope = ['token_introspection', self.aud]
        self.resource.save()
        self.token = create_fake_token(self.user, self.client.scope, self.client)
        self.token.access_token = str(random.randint(1, 999999)).zfill(6)
        self.now = time.time()
        with patch('oidc_provider.lib.utils.token.time.time') as time_func:
            time_func.return_value = self.now
            self.token.id_token = create_id_token(self.token, self.user, self.aud)
        self.token.save()

    def _assert_inactive(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(force_text(response.content), {'active': False})

    def _assert_active(self, response, **kwargs):
        self.assertEqual(response.status_code, 200)
        expected_content = {
            'active': True,
            'aud': self.aud,
            'client_id': self.client.client_id,
            'sub': str(self.user.pk),
            'iat': int(self.now),
            'exp': int(self.now + 600),
            'iss': 'http://localhost:8000/openid',
        }
        expected_content.update(kwargs)
        self.assertJSONEqual(force_text(response.content), expected_content)

    def _make_request(self, **kwargs):
        url = reverse('oidc_provider:token-introspection')
        data = {
            'client_id': kwargs.get('client_id', self.resource.client_id),
            'client_secret': kwargs.get('client_secret', self.resource.client_secret),
            'token': kwargs.get('access_token', self.token.access_token),
        }

        request = self.factory.post(url, data=urlencode(data),
                                    content_type='application/x-www-form-urlencoded')

        return TokenIntrospectionView.as_view()(request)

    def test_no_client_params_returns_inactive(self):
        response = self._make_request(client_id='')
        self._assert_inactive(response)

    def test_no_client_secret_returns_inactive(self):
        response = self._make_request(client_secret='')
        self._assert_inactive(response)

    def test_invalid_client_returns_inactive(self):
        response = self._make_request(client_id='invalid')
        self._assert_inactive(response)

    def test_token_not_found_returns_inactive(self):
        response = self._make_request(access_token='invalid')
        self._assert_inactive(response)

    def test_scope_no_audience_returns_inactive(self):
        self.resource.scope = ['token_introspection']
        self.resource.save()
        response = self._make_request()
        self._assert_inactive(response)

    def test_token_expired_returns_inactive(self):
        self.token.expires_at = timezone.now() - timezone.timedelta(seconds=60)
        self.token.save()
        response = self._make_request()
        self._assert_inactive(response)

    def test_valid_request_returns_default_properties(self):
        response = self._make_request()
        self._assert_active(response)

    @override_settings(OIDC_INTROSPECTION_PROCESSING_HOOK='oidc_provider.tests.app.utils.fake_introspection_processing_hook')  # NOQA
    def test_custom_introspection_hook_called_on_valid_request(self):
        response = self._make_request()
        self._assert_active(response, test_introspection_processing_hook=FAKE_RANDOM_STRING)

    @override_settings(OIDC_INTROSPECTION_VALIDATE_AUDIENCE_SCOPE=False)
    def test_disable_audience_validation(self):
        self.resource.scope = ['token_introspection']
        self.resource.save()
        response = self._make_request()
        self._assert_active(response)

    @override_settings(OIDC_INTROSPECTION_VALIDATE_AUDIENCE_SCOPE=False)
    def test_valid_client_grant_token_without_aud_validation(self):
        self.token.id_token = None  # client_credentials tokens do not have id_token
        self.token.save()
        self.resource.scope = ['token_introspection']
        self.resource.save()
        response = self._make_request()
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(force_text(response.content), {
            'active': True,
            'client_id': self.client.client_id,
        })
