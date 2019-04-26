import random

import time
from django.core.management import call_command
from mock import patch

from oidc_provider.lib.utils.token import create_id_token
from oidc_provider.models import Client, ResponseType
from oidc_provider.tests.app.utils import create_fake_token, create_fake_client, create_fake_user

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import RequestFactory, override_settings
from django.test import TestCase

from oidc_provider.views import RegisterView


@override_settings(OIDC_REGISTRATION_ENDPOINT_ENABLED=True)
class ProviderInfoTestCase(TestCase):
    """
        The Authorization Server attempts to register a new Client

        See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.aud = 'testaudience'
        self.data = '{' \
                    '"client_name": "client_name", ' \
                    '"response_types": ["code"], ' \
                    '"redirect_uris": ["http://localhost/"]' \
                    '}'
        self.client = create_fake_client(response_type='id_token token')

    @override_settings(OIDC_REGISTRATION_ENDPOINT_ENABLED=False)
    @override_settings(OIDC_REGISTRATION_ENDPOINT_REQ_TOKEN=False)
    def test_settings_disable(self):
        url = reverse('oidc_provider:register')

        request = self.factory.post(url, self.data, content_type="application/json")

        response = RegisterView.as_view()(request)

        self.assertEqual(response.status_code, 400)

    @override_settings(OIDC_REGISTRATION_ENDPOINT_REQ_TOKEN=True)
    def test_token_required_not_set(self):
        url = reverse('oidc_provider:register')
        request = self.factory.post(url, self.data, content_type="application/json")
        response = RegisterView.as_view()(request)

        self.assertEqual(response.status_code, 400)

    @override_settings(OIDC_REGISTRATION_ENDPOINT_REQ_TOKEN=False)
    @override_settings(OIDC_REGISTRATION_ENDPOINT_ALLOW_HTTP_ORIGIN=True)
    def test_register_without_token(self):
        url = reverse('oidc_provider:register')
        request = self.factory.post(url, self.data, content_type="application/json")
        request.META['HTTP_ORIGIN'] = 'http://origin.com'
        response = RegisterView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Access-Control-Allow-Origin"], 'http://origin.com')
        self.assertEqual(response["Access-Control-Allow-Methods"], 'POST')
        self.assertEqual(response["Access-Control-Allow-Headers"], 'Content-Type, if-match')

    @override_settings(OIDC_REGISTRATION_ENDPOINT_REQ_TOKEN=True)
    def test_register_with__insufficient_scope_token(self):
        url = reverse('oidc_provider:register')
        token = create_fake_token(self.user, self.client.scope, self.client)
        token.access_token = str(random.randint(1, 999999)).zfill(6)
        now = time.time()
        with patch('oidc_provider.lib.utils.token.time.time') as time_func:
            time_func.return_value = now
            token.id_token = create_id_token(token, self.user, self.aud)
        token.save()
        extra = {
            'HTTP_AUTHORIZATION': "Bearer {}".format(token.access_token)
        }
        request = self.factory.post(url, self.data, content_type="application/json", **extra)
        response = RegisterView.as_view()(request)

        self.assertEqual(response.status_code, 403)

    @override_settings(OIDC_REGISTRATION_ENDPOINT_REQ_TOKEN=True)
    def test_register_with_token(self):
        url = reverse('oidc_provider:register')
        token = create_fake_token(self.user, ["openid"], self.client)
        token.access_token = str(random.randint(1, 999999)).zfill(6)
        now = time.time()
        with patch('oidc_provider.lib.utils.token.time.time') as time_func:
            time_func.return_value = now
            token.id_token = create_id_token(token, self.user, self.aud)
        token.save()
        extra = {
            'HTTP_AUTHORIZATION': "Bearer {}".format(token.access_token)
        }
        request = self.factory.post(url, self.data, content_type="application/json", **extra)
        response = RegisterView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        client = Client.objects.get(name="client_name")
        self.assertEqual(client.response_types.all()[0], ResponseType.objects.get(value="code"))
        self.assertEqual(client._redirect_uris, "http://localhost/")
        self.assertNotIn('Access-Control-Allow-Origin', response)
