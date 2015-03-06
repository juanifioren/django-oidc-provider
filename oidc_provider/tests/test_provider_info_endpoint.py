from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase

from oidc_provider.views import *


class ProviderInfoTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def test_response(self):
        """
        See if the endpoint is returning the corresponding
        server information by checking status, content type, etc.
        """
        url = reverse('oidc_provider:provider_info')

        request = self.factory.get(url)

        response = ProviderInfoView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'] == 'application/json', True)
        self.assertEqual(bool(response.content), True)