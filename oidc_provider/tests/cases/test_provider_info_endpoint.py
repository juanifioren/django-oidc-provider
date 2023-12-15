from mock import patch

from django.core.cache import cache
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase, override_settings


from oidc_provider.views import ProviderInfoView


class ProviderInfoTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def tearDown(self):
        cache.clear()

    @patch('oidc_provider.views.ProviderInfoView._build_cache_key')
    def test_response(self, build_cache_key):
        """
        See if the endpoint is returning the corresponding
        server information by checking status, content type, etc.
        """
        url = reverse('oidc_provider:provider-info')

        request = self.factory.get(url)

        response = ProviderInfoView.as_view()(request)

        # Caching not available by default.
        build_cache_key.assert_not_called()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'] == 'application/json', True)
        self.assertEqual(bool(response.content), True)

    @override_settings(OIDC_DISCOVERY_CACHE_ENABLE=True)
    @patch('oidc_provider.views.ProviderInfoView._build_cache_key')
    def test_response_with_cache_enabled(self, build_cache_key):
        """
        Enable caching on the discovery endpoint and ensure data is being saved on cache.
        """
        build_cache_key.return_value = 'key'

        url = reverse('oidc_provider:provider-info')

        request = self.factory.get(url)

        response = ProviderInfoView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        build_cache_key.assert_called_once()

        assert 'authorization_endpoint' in cache.get('key')

        response = ProviderInfoView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'] == 'application/json', True)
        self.assertEqual(bool(response.content), True)
