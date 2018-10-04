from oidc_provider.lib.errors import RedirectUriError

try:
    from urllib.parse import urlencode, quote
except ImportError:
    from urllib import urlencode, quote
try:
    from urllib.parse import parse_qs, urlsplit
except ImportError:
    from urlparse import parse_qs, urlsplit
import uuid
from mock import patch, mock

from django.contrib.auth.models import AnonymousUser
from django.core.management import call_command
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import (
    RequestFactory,
    override_settings,
)
from django.test import TestCase
from jwkest.jwt import JWT

from oidc_provider import settings
from oidc_provider.tests.app.utils import (
    create_fake_user,
    create_fake_client,
    FAKE_CODE_CHALLENGE,
    is_code_valid,
)
from oidc_provider.lib.utils.authorize import strip_prompt_login
from oidc_provider.views import AuthorizeView
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint


class AuthorizeEndpointMixin(object):

    def _auth_request(self, method, data=None, is_user_authenticated=False):
        if data is None:
            data = {}
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


class AuthorizationCodeFlowTestCase(TestCase, AuthorizeEndpointMixin):
    """
    Test cases for Authorize Endpoint using Code Flow.
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')
        self.client_with_no_consent = create_fake_client(
            response_type='code', require_consent=False)
        self.client_public = create_fake_client(response_type='code', is_public=True)
        self.client_public_with_no_consent = create_fake_client(
            response_type='code', is_public=True, require_consent=False)
        self.state = uuid.uuid4().hex
        self.nonce = uuid.uuid4().hex

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
        self.assertIn('error=', response['Location'])

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
        self.assertIn(settings.get('OIDC_LOGIN_URL'), response['Location'])

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
            self.assertEqual(is_input_ok, True, msg='Hidden input for "' + key + '" fails.')

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
        self.assertIn('error=', response['Location'], msg='error param is missing in query.')
        self.assertIn(
            'access_denied', response['Location'], msg='"access_denied" code is missing in query.')

        # Simulate user authorization.
        data['allow'] = 'Accept'  # Will be the value of the button.

        response = self._auth_request('post', data, is_user_authenticated=True)

        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client)
        self.assertEqual(is_code_ok, True, msg='Code returned is invalid.')

        # Check if the state is returned.
        state = (response['Location'].split('state='))[1].split('&')[0]
        self.assertEqual(state, self.state, msg='State change or is missing.')

    def test_user_consent_skipped(self):
        """
        If users previously gave consent to some client (for a specific
        list of scopes) and because they might be prompted for the same
        authorization multiple times, the server skip it.
        """
        data = {
            'client_id': self.client_with_no_consent.client_id,
            'redirect_uri': self.client_with_no_consent.default_redirect_uri,
            'response_type': 'code',
            'scope': 'openid email',
            'state': self.state,
            'allow': 'Accept',
        }

        request = self.factory.post(reverse('oidc_provider:authorize'),
                                    data=data)
        # Simulate that the user is logged.
        request.user = self.user

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('code', response['Location'], msg='Code is missing in the returned url.')

        response = self._auth_request('post', data, is_user_authenticated=True)

        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client_with_no_consent)
        self.assertEqual(is_code_ok, True, msg='Code returned is invalid.')

        del data['allow']
        response = self._auth_request('get', data, is_user_authenticated=True)

        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client_with_no_consent)
        self.assertEqual(is_code_ok, True, msg='Code returned is invalid or missing.')

    def test_response_uri_is_properly_constructed(self):
        """
        Check that the redirect_uri matches the one configured for the client.
        Only 'state' and 'code' should be appended.
        """
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': 'code',
            'scope': 'openid email',
            'state': self.state,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        parsed = urlsplit(response['Location'])
        params = parse_qs(parsed.query or parsed.fragment)
        state = params['state'][0]
        self.assertEquals(self.state, state, msg="State returned is invalid or missing")

        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client)
        self.assertTrue(is_code_ok, msg='Code returned is invalid or missing')

        self.assertEquals(
            set(params.keys()), {'state', 'code'},
            msg='More than state or code appended as query params')

        self.assertTrue(
            response['Location'].startswith(self.client.default_redirect_uri),
            msg='Different redirect_uri returned')

    def test_unknown_redirect_uris_are_rejected(self):
        """
        If a redirect_uri is not registered with the client the request must be rejected.
        See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': 'code',
            'redirect_uri': 'http://neverseenthis.com',
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data)
        self.assertIn(
            RedirectUriError.error, response.content.decode('utf-8'), msg='No redirect_uri error')

    def test_manipulated_redirect_uris_are_rejected(self):
        """
        If a redirect_uri does not exactly match the registered uri it must be rejected.
        See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': 'code',
            'redirect_uri': self.client.default_redirect_uri + "?some=query",
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data)
        self.assertIn(
            RedirectUriError.error, response.content.decode('utf-8'), msg='No redirect_uri error')

    def test_public_client_auto_approval(self):
        """
        It's recommended not auto-approving requests for non-confidential
        clients using Authorization Code.
        """
        data = {
            'client_id': self.client_public_with_no_consent.client_id,
            'response_type': 'code',
            'redirect_uri': self.client_public_with_no_consent.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data, is_user_authenticated=True)

        self.assertIn('Request for Permission', response.content.decode('utf-8'))

    def test_prompt_none_parameter(self):
        """
        Specifies whether the Authorization Server prompts the End-User for
        reauthentication and consent.
        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': next(self.client.response_type_values()),
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
            'prompt': 'none'
        }

        response = self._auth_request('get', data)

        # An error is returned if an End-User is not already authenticated.
        self.assertIn('login_required', response['Location'])

        response = self._auth_request('get', data, is_user_authenticated=True)

        # An error is returned if the Client does not have pre-configured
        # consent for the requested Claims.
        self.assertIn('consent_required', response['Location'])

    @patch('oidc_provider.views.django_user_logout')
    def test_prompt_login_parameter(self, logout_function):
        """
        Specifies whether the Authorization Server prompts the End-User for
        reauthentication and consent.
        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': next(self.client.response_type_values()),
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
            'prompt': 'login'
        }

        response = self._auth_request('get', data)
        self.assertIn(settings.get('OIDC_LOGIN_URL'), response['Location'])
        self.assertNotIn(
            quote('prompt=login'),
            response['Location'],
            "Found prompt=login, this leads to infinite login loop. See "
            "https://github.com/juanifioren/django-oidc-provider/issues/197."
        )

        response = self._auth_request('get', data, is_user_authenticated=True)
        self.assertIn(settings.get('OIDC_LOGIN_URL'), response['Location'])
        self.assertTrue(logout_function.called_once())
        self.assertNotIn(
            quote('prompt=login'),
            response['Location'],
            "Found prompt=login, this leads to infinite login loop. See "
            "https://github.com/juanifioren/django-oidc-provider/issues/197."
        )

    def test_prompt_login_none_parameter(self):
        """
        Specifies whether the Authorization Server prompts the End-User for
        reauthentication and consent.
        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': next(self.client.response_type_values()),
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
            'prompt': 'login none'
        }

        response = self._auth_request('get', data)
        self.assertIn('login_required', response['Location'])

        response = self._auth_request('get', data, is_user_authenticated=True)
        self.assertIn('login_required', response['Location'])

    @patch('oidc_provider.views.render')
    def test_prompt_consent_parameter(self, render_patched):
        """
        Specifies whether the Authorization Server prompts the End-User for
        reauthentication and consent.
        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': next(self.client.response_type_values()),
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
            'prompt': 'consent'
        }

        response = self._auth_request('get', data)
        self.assertIn(settings.get('OIDC_LOGIN_URL'), response['Location'])

        response = self._auth_request('get', data, is_user_authenticated=True)
        render_patched.assert_called_once()
        self.assertTrue(
            render_patched.call_args[0][1], settings.get('OIDC_TEMPLATES')['authorize'])

    def test_prompt_consent_none_parameter(self):
        """
        Specifies whether the Authorization Server prompts the End-User for
        reauthentication and consent.
        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': next(self.client.response_type_values()),
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
            'prompt': 'consent none'
        }

        response = self._auth_request('get', data)
        self.assertIn('login_required', response['Location'])

        response = self._auth_request('get', data, is_user_authenticated=True)
        self.assertIn('consent_required', response['Location'])

    def test_strip_prompt_login(self):
        """
        Test for helper method test_strip_prompt_login.
        """
        # Original paths
        path0 = 'http://idp.com/?prompt=login'
        path1 = 'http://idp.com/?prompt=consent login none'
        path2 = ('http://idp.com/?response_type=code&client' +
                 '_id=112233&prompt=consent login')
        path3 = ('http://idp.com/?response_type=code&client' +
                 '_id=112233&prompt=login none&redirect_uri' +
                 '=http://localhost:8000')

        self.assertNotIn('prompt', strip_prompt_login(path0))

        self.assertIn('prompt', strip_prompt_login(path1))
        self.assertIn('consent', strip_prompt_login(path1))
        self.assertIn('none', strip_prompt_login(path1))
        self.assertNotIn('login', strip_prompt_login(path1))

        self.assertIn('prompt', strip_prompt_login(path2))
        self.assertIn('consent', strip_prompt_login(path1))
        self.assertNotIn('login', strip_prompt_login(path2))

        self.assertIn('prompt', strip_prompt_login(path3))
        self.assertIn('none', strip_prompt_login(path3))
        self.assertNotIn('login', strip_prompt_login(path3))


class AuthorizationImplicitFlowTestCase(TestCase, AuthorizeEndpointMixin):
    """
    Test cases for Authorization Endpoint using Implicit Flow.
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='id_token token')
        self.client_public = create_fake_client(response_type='id_token token', is_public=True)
        self.client_public_no_consent = create_fake_client(
            response_type='id_token token', is_public=True,
            require_consent=False)
        self.client_no_access = create_fake_client(response_type='id_token')
        self.client_public_no_access = create_fake_client(response_type='id_token', is_public=True)
        self.client_multiple_response_types = create_fake_client(
            response_type=('id_token', 'id_token token'))
        self.state = uuid.uuid4().hex
        self.nonce = uuid.uuid4().hex

    def test_missing_nonce(self):
        """
        The `nonce` parameter is REQUIRED if you use the Implicit Flow.
        """
        data = {
            'client_id': self.client.client_id,
            'response_type': next(self.client.response_type_values()),
            'redirect_uri': self.client.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
        }

        response = self._auth_request('get', data, is_user_authenticated=True)

        self.assertIn('#error=invalid_request', response['Location'])

    def test_idtoken_token_response(self):
        """
        Implicit client requesting `id_token token` receives both id token
        and access token as the result of the authorization request.
        """
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': next(self.client.response_type_values()),
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

        # same for public client
        data['client_id'] = self.client_public.client_id,
        data['redirect_uri'] = self.client_public.default_redirect_uri,
        data['response_type'] = next(self.client_public.response_type_values()),

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

    def test_idtoken_response(self):
        """
        Implicit client requesting `id_token` receives
        only an id token as the result of the authorization request.
        """
        data = {
            'client_id': self.client_no_access.client_id,
            'redirect_uri': self.client_no_access.default_redirect_uri,
            'response_type': next(self.client_no_access.response_type_values()),
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertNotIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

        # same for public client
        data['client_id'] = self.client_public_no_access.client_id,
        data['redirect_uri'] = self.client_public_no_access.default_redirect_uri,
        data['response_type'] = next(self.client_public_no_access.response_type_values()),

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertNotIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

    def test_idtoken_token_at_hash(self):
        """
        Implicit client requesting `id_token token` receives
        `at_hash` in `id_token`.
        """
        data = {
            'client_id': self.client.client_id,
            'redirect_uri': self.client.default_redirect_uri,
            'response_type': next(self.client.response_type_values()),
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('id_token', response['Location'])

        # obtain `id_token` portion of Location
        components = urlsplit(response['Location'])
        fragment = parse_qs(components[4])
        id_token = JWT().unpack(fragment["id_token"][0].encode('utf-8')).payload()

        self.assertIn('at_hash', id_token)

    def test_idtoken_at_hash(self):
        """
        Implicit client requesting `id_token` should not receive
        `at_hash` in `id_token`.
        """
        data = {
            'client_id': self.client_no_access.client_id,
            'redirect_uri': self.client_no_access.default_redirect_uri,
            'response_type': next(self.client_no_access.response_type_values()),
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('id_token', response['Location'])

        # obtain `id_token` portion of Location
        components = urlsplit(response['Location'])
        fragment = parse_qs(components[4])
        id_token = JWT().unpack(fragment["id_token"][0].encode('utf-8')).payload()

        self.assertNotIn('at_hash', id_token)

    def test_public_client_implicit_auto_approval(self):
        """
        Public clients using Implicit Flow should be able to reuse consent.
        """
        data = {
            'client_id': self.client_public_no_consent.client_id,
            'response_type': next(self.client_public_no_consent.response_type_values()),
            'redirect_uri': self.client_public_no_consent.default_redirect_uri,
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
        }

        response = self._auth_request('get', data, is_user_authenticated=True)
        response_text = response.content.decode('utf-8')
        self.assertEquals(response_text, '')
        components = urlsplit(response['Location'])
        fragment = parse_qs(components[4])
        self.assertIn('access_token', fragment)
        self.assertIn('id_token', fragment)
        self.assertIn('expires_in', fragment)

    def test_multiple_response_types(self):
        """
        Clients should be able to be configured for multiple response types.
        """
        data = {
            'client_id': self.client_multiple_response_types.client_id,
            'redirect_uri': self.client_multiple_response_types.default_redirect_uri,
            'response_type': 'id_token',
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertNotIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])

        # should also support "id_token token" response_type
        data['response_type'] = 'id_token token'

        response = self._auth_request('post', data, is_user_authenticated=True)

        self.assertIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])


class AuthorizationHybridFlowTestCase(TestCase, AuthorizeEndpointMixin):
    """
    Test cases for Authorization Endpoint using Hybrid Flow.
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client_code_idtoken_token = create_fake_client(
            response_type='code id_token token', is_public=True)
        self.state = uuid.uuid4().hex
        self.nonce = uuid.uuid4().hex

        # Base data for the auth request.
        self.data = {
            'client_id': self.client_code_idtoken_token.client_id,
            'redirect_uri': self.client_code_idtoken_token.default_redirect_uri,
            'response_type': next(self.client_code_idtoken_token.response_type_values()),
            'scope': 'openid email',
            'state': self.state,
            'nonce': self.nonce,
            'allow': 'Accept',
        }

    def test_code_idtoken_token_response(self):
        """
        Implicit client requesting `id_token token` receives both id token
        and access token as the result of the authorization request.
        """
        response = self._auth_request('post', self.data, is_user_authenticated=True)

        self.assertIn('#', response['Location'])
        self.assertIn('access_token', response['Location'])
        self.assertIn('id_token', response['Location'])
        self.assertIn('state', response['Location'])
        self.assertIn('code', response['Location'])

        # Validate code.
        is_code_ok = is_code_valid(url=response['Location'],
                                   user=self.user,
                                   client=self.client_code_idtoken_token)
        self.assertEqual(is_code_ok, True, msg='Code returned is invalid.')

    @override_settings(OIDC_TOKEN_EXPIRE=36000)
    def test_access_token_expiration(self):
        """
        Add ten hours of expiration to access_token. Check for the expires_in query in fragment.
        """
        response = self._auth_request('post', self.data, is_user_authenticated=True)

        self.assertIn('expires_in=36000', response['Location'])


class TestCreateResponseURI(TestCase):
    def setUp(self):
        url = reverse('oidc_provider:authorize')
        user = create_fake_user()
        client = create_fake_client(response_type='code', is_public=True)

        # Base data to create a uri response
        data = {
            'client_id': client.client_id,
            'redirect_uri': client.default_redirect_uri,
            'response_type': next(client.response_type_values()),
        }

        factory = RequestFactory()
        self.request = factory.post(url, data=data)
        self.request.user = user

    @patch('oidc_provider.lib.endpoints.authorize.create_code')
    @patch('oidc_provider.lib.endpoints.authorize.logger.exception')
    def test_create_response_uri_logs_to_error(self, log_exception, create_code):
        """
        A lot can go wrong when creating a response uri and this is caught
        with a general Exception error. The information contained within this
        error should show up in the error log so production servers have something
        to work with when things don't work as expected.
        """
        exception = Exception("Something went wrong!")
        create_code.side_effect = exception

        authorization_endpoint = AuthorizeEndpoint(self.request)
        authorization_endpoint.validate_params()

        with self.assertRaises(Exception):
            authorization_endpoint.create_response_uri()

        log_exception.assert_called_once_with(
            '[Authorize] Error when trying to create response uri: %s', exception)

    @override_settings(OIDC_SESSION_MANAGEMENT_ENABLE=True)
    def test_create_response_uri_generates_session_state_if_session_management_enabled(self):
        # RequestFactory doesn't support sessions, so we mock it
        self.request.session = mock.Mock(session_key=None)

        authorization_endpoint = AuthorizeEndpoint(self.request)
        authorization_endpoint.validate_params()

        uri = authorization_endpoint.create_response_uri()
        self.assertIn('session_state=', uri)
