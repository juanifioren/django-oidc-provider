try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase

from oidc_provider.models import ResponseType
from oidc_provider.views import ProviderInfoView


class ProviderInfoTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def test_response(self):
        """
        See if the endpoint is returning the corresponding
        server information by checking status, content type, etc.
        """
        url = reverse('oidc_provider:provider-info')

        request = self.factory.get(url)

        response = ProviderInfoView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'] == 'application/json', True)
        self.assertEqual(bool(response.content), True)

    def test_supported_response_types_property(self):
        view = ProviderInfoView()

        self.assertEqual(len(view.supported_response_types), 6)

        ResponseType.objects.create(value="foo", description="bar")

        self.assertEqual(len(view.supported_response_types), 6)

        del view.__dict__['supported_response_types']
        self.assertEqual(len(view.supported_response_types), 7)
