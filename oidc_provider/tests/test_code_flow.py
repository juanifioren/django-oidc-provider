from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.models import AnonymousUser
from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase
from oidc_provider import settings
from oidc_provider.tests.utils import *
from oidc_provider.views import *
import urllib


class CodeFlowTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')

    def _create_authorize_url(self, response_type, scope=['openid', 'email']):
        """
        Generate an OpenID Authentication Request using the fake client data.
        """
        path = reverse('oidc_provider:authorize')

        query_str = urllib.urlencode({
            'client_id': self.client.client_id,
            'response_type': response_type,
            'redirect_uri': self.client.default_redirect_uri,
            'scope': ' '.join(scope),
            'state': 'abcdefg',
        }).replace('+', '%20')

        url = path + '?' + query_str

        return url

    def test_authorize_invalid_parameters(self):
        """
        If the request fails due to a missing, invalid, or mismatching
        redirection URI, or if the client identifier is missing or invalid,
        the authorization server SHOULD inform the resource owner of the error.

        See: https://tools.ietf.org/html/rfc6749#section-4.1.2.1
        """
        url = reverse('oidc_provider:authorize')
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
        url = self._create_authorize_url(response_type='code id_token')

        request = self.factory.get(url)

        response = AuthorizeView.as_view()(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.has_header('Location'), True)

        # Should be an 'error' component in query.
        query_exists = 'error=' in response['Location']
        self.assertEqual(query_exists, True)

    def test_authorize_user_not_logged(self):
        """
        The Authorization Server attempts to Authenticate the End-User by
        redirecting to the login view.

        See: http://openid.net/specs/openid-connect-core-1_0.html#Authenticates
        """
        url = self._create_authorize_url(response_type='code')

        request = self.factory.get(url)
        request.user = AnonymousUser()

        response = AuthorizeView.as_view()(request)

        # Check if user was redirected to the login view.
        login_url_exists = settings.get('LOGIN_URL') in response['Location']
        self.assertEqual(login_url_exists, True)

        # Check if the login will redirect to a valid url.
        try:
            next_value = response['Location'].split(REDIRECT_FIELD_NAME + '=')[1]
            next_url = urllib.unquote(next_value)
            is_next_ok = next_url == url
        except:
            is_next_ok = False
        self.assertEqual(is_next_ok, True)

    def test_authorize_user_consent(self):
        url = self._create_authorize_url(response_type='code')

        request = self.factory.get(url)
        # Simulate that the user is logged.
        request.user = self.user

        response = AuthorizeView.as_view()(request)

        import pdb; pdb.set_trace()