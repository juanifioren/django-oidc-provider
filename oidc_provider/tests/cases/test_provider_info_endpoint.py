import json

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import RequestFactory, TestCase, override_settings

from oidc_provider.views import ProviderInfoView


class ProviderInfoTestCase(TestCase):

    @classmethod
    def setUpClass(cls):
        super(ProviderInfoTestCase, cls).setUpClass()
        cls.url = reverse('oidc_provider:provider-info')

    def setUp(self):
        self.factory = RequestFactory()

    def test_response(self):
        """
        See if the endpoint is returning the corresponding
        server information by checking status, content type, etc.
        """

        request = self.factory.get(self.url)

        response = ProviderInfoView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'] == 'application/json', True)
        self.assertEqual(bool(response.content), True)

    def test_expected_keys_in_response(self):
        """
        Test that response contains all ncecessary keys
        """
        required_keys = {
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'end_session_endpoint',
            'introspection_endpoint',
            'response_types_supported',
            'jwks_uri',
            'id_token_signing_alg_values_supported',
            'subject_types_supported',
            'token_endpoint_auth_methods_supported',
            'claims_supported',
        }

        request = self.factory.get(self.url)

        response = ProviderInfoView.as_view()(request)
        resp_keys = set(json.loads(response.content.decode('utf-8')).keys())
        self.assertEqual(required_keys, resp_keys)

    def test_claims_supported_not_set(self):
        """
        If OIDC_CLAIMS_SUPPORTED is not set in settings.py, the claims_supported
        entry is an empty list
        """
        request = self.factory.get(self.url)

        response = ProviderInfoView.as_view()(request)
        dic = json.loads(response.content.decode('utf-8'))
        self.assertEqual(dic['claims_supported'], [])

    @override_settings(OIDC_CLAIMS_SUPPORTED=['openid', 'email'])
    def test_claims_supported_set(self):
        """
        If OIDC_CLAIMS_SUPPORTED is not set in settings.py, the claims_supported
        entry is an empty list
        """
        expected_claims = ['openid', 'email']

        request = self.factory.get(self.url)

        response = ProviderInfoView.as_view()(request)
        dic = json.loads(response.content.decode('utf-8'))
        self.assertEqual(dic['claims_supported'], expected_claims)
