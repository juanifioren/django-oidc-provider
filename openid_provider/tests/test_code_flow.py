from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase
from openid_provider.tests.utils import *
from openid_provider.views import *
import urllib


class CodeFlowTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')

    def test_authorize_invalid_parameters(self):
        """
        If the request fails due to a missing, invalid, or mismatching
        redirection URI, or if the client identifier is missing or invalid,
        the authorization server SHOULD inform the resource owner of the error.

        See: https://tools.ietf.org/html/rfc6749#section-4.1.2.1
        """
        url = reverse('openid_provider:authorize')
        request = self.factory.get(url)

        response = AuthorizeView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(bool(response.content), True)

    def test_authorize_invalid_response_type(self):
        """
        The OP informs the RP by using the Error Response parameters defined
        in Section 4.1.2.1 of OAuth 2.0.

        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthError
        """
        # Create an authorize request with an unsupported response_type.
        url = reverse('openid_provider:authorize')
        url += '?client_id={0}&response_type=code%20id_token&scope=openid%20email' \
               '&redirect_uri={1}&state=abcdefg'.format(
                    self.client.client_id,
                    urllib.quote(self.client.default_redirect_uri),
                )
        request = self.factory.get(url)

        response = AuthorizeView.as_view()(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.has_header('Location'), True)

        # Check query component in the redirection URI.
        correct_query = 'error=' in response['Location']
        self.assertEqual(correct_query, True)