try:
    from urllib.parse import unquote, urlencode
except ImportError:
    from urllib import unquote, urlencode
import uuid

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.models import AnonymousUser
from django.core.management import call_command
from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase

from oidc_provider import settings
from oidc_provider.models import *
from oidc_provider.tests.app.utils import *
from oidc_provider.views import *


class AuthorizationCodeFlowTestCase(TestCase):
    """
    Test cases for Authorize Endpoint using Authorization Code Flow.
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')
        self.client_public = create_fake_client(response_type='code', is_public=True)
        self.client_implicit = create_fake_client(response_type='id_token token')
        self.state = uuid.uuid4().hex
        self.nonce = uuid.uuid4().hex

    def _auth_request(self, method, data={}, is_user_authenticated=False):
        url = reverse('oidc_provider:authorize')

        if method.lower() == 'get':
            query_str = urlencode(data).replace('+', '%20')
            if query_str:
                url += '?' + query_str
            request = self.factory.get(url)
        elif method.lower() == 'post':
            request = self.factory.post(url, data=data)
        else:
            raise Exception('Method unsupported for an Authorization Request.')

        # Simulate that the user is logged.
        request.user = self.user if is_user_authenticated else AnonymousUser()

        response = AuthorizeView.as_view()(request)

        return response


    def test_missing_parameters(self):
        """
        If the request fails due to a missing, invalid, or mismatching
        redirection URI, or if the client identifier is missing or invalid,
        the authorization server SHOULD inform the resource owner of the error.

        See: https://tools.ietf.org/html/rfc6749#section-4.1.2.1
        """
        response = self._auth_request('get')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(bool(response.content), True)

    def test_invalid_response_type(self):
        """
        The OP informs the RP by using the Error Response parameters defined
        in Section 4.1.2.1 of OAuth 2.0.

        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthError
        """
        # Create an authorize request with an unsupported response_type.
        data = {
            'client_id': self.client.client_id,
            'response_type': 'something_wrong',
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.has_header('Location'), True)

        # Should be an 'error' component in query.
        query_exists = 'error=' in response['Location']
        self.assertEqual(query_exists, True)

    def test_user_not_logged(self):
        """
        The Authorization Server attempts to Authenticate the End-User by
        redirecting to the login view.

        See: http://openid.net/specs/openid-connect-core-1_0.html#Authenticates
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': 'code',
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data)

        # Check if user was redirected to the login view.
        login_url_exists = settings.get('LOGIN_URL') in response['Location']
        self.assertEqual(login_url_exists, True)

    def test_user_consent_inputs(self):
        """
        Once the End-User is authenticated, the Authorization Server MUST
        obtain an authorization decision before releasing information to
        the Client.

        See: http://openid.net/specs/openid-connect-core-1_0.html#Consent
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': 'code',
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
            # PKCE parameters.
            'code_challenge': FAKE_CODE_CHALLENGE,
            'code_challenge_method': 'S256',
        }

        response = self._auth_request('get', data, is_user_authenticated=True)

        # Check if hidden inputs exists in the form,
        # also if their values are valid.
        input_html = '<input name="{0}" type="hidden" value="{1}" />'

        to_check = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': 'code',
            'code_challenge': FAKE_CODE_CHALLENGE,
            'code_challenge_method': 'S256',
        }

        for key, value in iter(to_check.items()):
            is_input_ok = input_html.format(key, value) in response.content.decode('utf-8')
            self.assertEqual(is_input_ok, True,
                msg='Hidden input for "'+key+'" fails.')

    def test_user_consent_response(self):
        """
        First,
        if the user denied the consent we must ensure that
        the error response parameters are added to the query component
        of the Redirection URI.

        Second,
        if the user allow the RP then the server MUST return
        the parameters defined in Section 4.1.2 of OAuth 2.0 [RFC6749]
        by adding them as query parameters to the redirect_uri.
        """
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': 'code',
            'scope': 'openid email',
            'state': self.state,
            # PKCE parameters.
            'code_challenge': FAKE_CODE_CHALLENGE,
            'code_challenge_method': 'S256',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        # Because user doesn't allow app, SHOULD exists an error parameter
        # in the query.
        self.assertEqual('error=' in response['Location'], True,
            msg='error param is missing in query.')
        self.assertEqual('access_denied' in response['Location'], True,
            msg='"access_denied" code is missing in query.')

        # Simulate user authorization.
        data['allow'] = 'Accept' # Will be the value of the button.

        response = self._auth_request('post', data, is_user_authenticated=True)

        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client)
        self.assertEqual(is_code_ok, True,
            msg='Code returned is invalid.')

        # Check if the state is returned.
        state = (response['Location'].split('state='))[1].split('&')[0]
        self.assertEqual(state == self.state, True,
            msg='State change or is missing.')

    def test_user_consent_skipped(self):
        """
        If users previously gave consent to some client (for a specific
        list of scopes) and because they might be prompted for the same
        authorization multiple times, the server skip it.
        """
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': 'code',
            'scope': 'openid email',
            'state': self.state,
            'allow': 'Accept',
        }

        request = self.factory.post(reverse('oidc_provider:authorize'),
                                    data=data)
        # Simulate that the user is logged.
        request.user = self.user

        with self.settings(OIDC_SKIP_CONSENT_ALWAYS=True):
            response = self._auth_request('post', data, is_user_authenticated=True)

            self.assertEqual('code' in response['Location'], True,
                msg='Code is missing in the returned url.')

        response = self._auth_request('post', data, is_user_authenticated=True)

        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client)
        self.assertEqual(is_code_ok, True, msg='Code returned is invalid.')

        del data['allow']
        response = self._auth_request('get', data, is_user_authenticated=True)

        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client)
        self.assertEqual(is_code_ok, True, msg='Code returned is invalid or missing.')

    def test_response_uri_is_properly_constructed(self):
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri + "?redirect_state=xyz",
            'response_type': 'code',
            'scope': 'openid email',
            'state': self.state,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        # TODO

    def test_public_client_auto_approval(self):
        """
        It's recommended not auto-approving requests for non-confidential clients.
        """
        data = {
            'client_id': self.client_public.client_id,
            'response_type': 'code',
            'redirect_uri': self.client_public.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        with self.settings(OIDC_SKIP_CONSENT_ALWAYS=True):
            response = self._auth_request('get', data, is_user_authenticated=True)

        self.assertEqual('Request for Permission' in response.content.decode('utf-8'), True)

    def test_implicit_missing_nonce(self):
        """
        The `nonce` parameter is REQUIRED if you use the Implicit Flow.
        """
        data = {
            'client_id': self.client_implicit.client_id,
            'response_type': self.client_implicit.response_type,
            'redirect_uri': self.client_implicit.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data, is_user_authenticated=True)
        
        self.assertEqual('#error=invalid_request' in response['Location'], True)   

    def test_implicit_access_token_response(self):
        """
        Unlike the Authorization Code flow, in which the client makes
        separate requests for authorization and for an access token, the client
        receives the access token as the result of the authorization request.
        """
        data = {
            'client_id': self.client_implicit.client_id,
            'redirect_uri': self.client_implicit.default_redirect_uri,
            'response_type': self.client_implicit.response_type,
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)
        
        self.assertEqual('access_token' in response['Location'], True)


    def test_prompt_parameter(self):
        """
        Specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': self.client.response_type,
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        data['prompt'] = 'none'

        response = self._auth_request('get', data)

        # An error is returned if an End-User is not already authenticated.
        self.assertEqual('login_required' in response['Location'], True)

        response = self._auth_request('get', data, is_user_authenticated=True)

        # An error is returned if the Client does not have pre-configured consent for the requested Claims.
        self.assertEqual('interaction_required' in response['Location'], True)
