import json
import time
import uuid

from base64 import b64encode

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

from django.core.management import call_command
from django.http import JsonResponse
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import (
    RequestFactory,
    override_settings,
)
from django.test import TestCase
from django.views.decorators.http import require_http_methods
from jwkest.jwk import KEYS
from jwkest.jws import JWS
from jwkest.jwt import JWT
from mock import patch

from oidc_provider.lib.endpoints.introspection import INTROSPECTION_SCOPE
from oidc_provider.lib.utils.oauth2 import protected_resource_view
from oidc_provider.lib.utils.token import create_code
from oidc_provider.models import Token
from oidc_provider.tests.app.utils import (
    create_fake_user,
    create_fake_client,
    FAKE_CODE_CHALLENGE,
    FAKE_CODE_VERIFIER,
    FAKE_NONCE,
    FAKE_RANDOM_STRING,
)
from oidc_provider.views import (
    JwksView,
    TokenView,
    userinfo,
)


class TokenTestCase(TestCase):
    """
    To obtain an Access Token and an ID Token, the RP Client sends a
    Token Request to the Token Endpoint to obtain a Token Response
    when using the Authorization Code Flow.
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.request_client = self.client
        self.client = create_fake_client(response_type='code')

    def _password_grant_post_data(self, scope=None):
        result = {
            'username': 'johndoe',
            'password': '1234',
            'grant_type': 'password',
            'scope': 'openid email',
        }
        if scope is not None:
            result['scope'] = ' '.join(scope)
        return result

    def _auth_code_post_data(self, code, scope=None):
        """
        All the data that will be POSTed to the Token Endpoint.
        """
        post_data = {
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret,
            'redirect_uri': self.client.default_redirect_uri,
            'grant_type': 'authorization_code',
            'code': code,
            'state': uuid.uuid4().hex,
        }
        if scope is not None:
            post_data['scope'] = ' '.join(scope)

        return post_data

    def _refresh_token_post_data(self, refresh_token, scope=None):
        """
        All the data that will be POSTed to the Token Endpoint.
        """
        post_data = {
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }
        if scope is not None:
            post_data['scope'] = ' '.join(scope)

        return post_data

    def _post_request(self, post_data, extras={}):
        """
        Makes a request to the token endpoint by sending the
        `post_data` parameters using the 'application/x-www-form-urlencoded'
        format.
        """
        url = reverse('oidc_provider:token')

        request = self.factory.post(
            url,
            data=urlencode(post_data),
            content_type='application/x-www-form-urlencoded',
            **extras)

        response = TokenView.as_view()(request)

        return response

    def _create_code(self, scope=None):
        """
        Generate a valid grant code.
        """
        code = create_code(
            user=self.user,
            client=self.client,
            scope=(scope if scope else ['openid', 'email']),
            nonce=FAKE_NONCE,
            is_authentication=True)
        code.save()

        return code

    def _get_keys(self):
        """
        Get public key from discovery.
        """
        request = self.factory.get(reverse('oidc_provider:jwks'))
        response = JwksView.as_view()(request)
        jwks_dic = json.loads(response.content.decode('utf-8'))
        SIGKEYS = KEYS()
        SIGKEYS.load_dict(jwks_dic)
        return SIGKEYS

    def _get_userinfo(self, access_token):
        url = reverse('oidc_provider:userinfo')
        request = self.factory.get(url)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer ' + access_token

        return userinfo(request)

    def _password_grant_auth_header(self):
        user_pass = self.client.client_id + ':' + self.client.client_secret
        auth = b'Basic ' + b64encode(user_pass.encode('utf-8'))
        auth_header = {'HTTP_AUTHORIZATION': auth.decode('utf-8')}
        return auth_header

    def test_default_setting_does_not_allow_grant_type_password(self):
        post_data = self._password_grant_post_data()

        response = self._post_request(
            post_data=post_data,
            extras=self._password_grant_auth_header()
        )

        response_dict = json.loads(response.content.decode('utf-8'))

        self.assertEqual(400, response.status_code)
        self.assertEqual('unsupported_grant_type', response_dict['error'])

    @override_settings(OIDC_GRANT_TYPE_PASSWORD_ENABLE=True)
    def test_password_grant_get_access_token_without_scope(self):
        post_data = self._password_grant_post_data()
        del (post_data['scope'])

        response = self._post_request(
            post_data=post_data,
            extras=self._password_grant_auth_header()
        )

        response_dict = json.loads(response.content.decode('utf-8'))
        self.assertIn('access_token', response_dict)

    @override_settings(OIDC_GRANT_TYPE_PASSWORD_ENABLE=True)
    def test_password_grant_get_access_token_with_scope(self):
        response = self._post_request(
            post_data=self._password_grant_post_data(),
            extras=self._password_grant_auth_header()
        )

        response_dict = json.loads(response.content.decode('utf-8'))
        self.assertIn('access_token', response_dict)

    @override_settings(OIDC_GRANT_TYPE_PASSWORD_ENABLE=True)
    def test_password_grant_get_access_token_invalid_user_credentials(self):
        invalid_post = self._password_grant_post_data()
        invalid_post['password'] = 'wrong!'

        response = self._post_request(
            post_data=invalid_post,
            extras=self._password_grant_auth_header()
        )

        response_dict = json.loads(response.content.decode('utf-8'))

        self.assertEqual(403, response.status_code)
        self.assertEqual('access_denied', response_dict['error'])

    def test_password_grant_get_access_token_invalid_client_credentials(self):
        self.client.client_id = 'foo'
        self.client.client_secret = 'bar'

        response = self._post_request(
            post_data=self._password_grant_post_data(),
            extras=self._password_grant_auth_header()
        )

        response_dict = json.loads(response.content.decode('utf-8'))

        self.assertEqual(400, response.status_code)
        self.assertEqual('invalid_client', response_dict['error'])

    def test_password_grant_full_response(self):
        self.check_password_grant(scope=['openid', 'email'])

    def test_password_grant_scope(self):
        self.check_password_grant(scope=['openid', 'profile'])

    @override_settings(OIDC_TOKEN_EXPIRE=120,
                       OIDC_GRANT_TYPE_PASSWORD_ENABLE=True)
    def check_password_grant(self, scope):
        response = self._post_request(
            post_data=self._password_grant_post_data(scope),
            extras=self._password_grant_auth_header()
        )

        response_dict = json.loads(response.content.decode('utf-8'))
        id_token = JWS().verify_compact(
            response_dict['id_token'].encode('utf-8'), self._get_keys())

        token = Token.objects.get(user=self.user)
        self.assertEqual(response_dict['access_token'], token.access_token)
        self.assertEqual(response_dict['refresh_token'], token.refresh_token)
        self.assertEqual(response_dict['expires_in'], 120)
        self.assertEqual(response_dict['token_type'], 'bearer')
        self.assertEqual(id_token['sub'], str(self.user.id))
        self.assertEqual(id_token['aud'], self.client.client_id)

        # Check the scope is honored by checking the claims in the userinfo
        userinfo_response = self._get_userinfo(response_dict['access_token'])
        userinfo = json.loads(userinfo_response.content.decode('utf-8'))

        for (scope_param, claim) in [('email', 'email'), ('profile', 'name')]:
            if scope_param in scope:
                self.assertIn(claim, userinfo)
            else:
                self.assertNotIn(claim, userinfo)

    @override_settings(OIDC_GRANT_TYPE_PASSWORD_ENABLE=True,
                       AUTHENTICATION_BACKENDS=("oidc_provider.tests.app.utils.TestAuthBackend",))
    def test_password_grant_passes_request_to_backend(self):
        response = self._post_request(
            post_data=self._password_grant_post_data(),
            extras=self._password_grant_auth_header()
        )

        response_dict = json.loads(response.content.decode('utf-8'))
        self.assertIn('access_token', response_dict)

    @override_settings(OIDC_TOKEN_EXPIRE=720)
    def test_authorization_code(self):
        """
        We MUST validate the signature of the ID Token according to JWS
        using the algorithm specified in the alg Header Parameter of
        the JOSE Header.
        """
        SIGKEYS = self._get_keys()
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)
        response_dic = json.loads(response.content.decode('utf-8'))

        id_token = JWS().verify_compact(response_dic['id_token'].encode('utf-8'), SIGKEYS)

        token = Token.objects.get(user=self.user)
        self.assertEqual(response_dic['access_token'], token.access_token)
        self.assertEqual(response_dic['refresh_token'], token.refresh_token)
        self.assertEqual(response_dic['token_type'], 'bearer')
        self.assertEqual(response_dic['expires_in'], 720)
        self.assertEqual(id_token['sub'], str(self.user.id))
        self.assertEqual(id_token['aud'], self.client.client_id)

    @override_settings(OIDC_TOKEN_EXPIRE=720,
                       OIDC_IDTOKEN_INCLUDE_CLAIMS=True)
    def test_scope_is_ignored_for_auth_code(self):
        """
        Scope is ignored for token respones to auth code grant type.
        This comes down to that the scopes requested in authorize are returned.
        """
        SIGKEYS = self._get_keys()
        for code_scope in [['openid'], ['openid', 'email'], ['openid', 'profile']]:
            code = self._create_code(code_scope)

            post_data = self._auth_code_post_data(
                code=code.code, scope=code_scope)

            response = self._post_request(post_data)
            response_dic = json.loads(response.content.decode('utf-8'))

            self.assertEqual(response.status_code, 200)

            id_token = JWS().verify_compact(response_dic['id_token'].encode('utf-8'), SIGKEYS)

            if 'email' in code_scope:
                self.assertIn('email', id_token)
                self.assertIn('email_verified', id_token)
            else:
                self.assertNotIn('email', id_token)

            if 'profile' in code_scope:
                self.assertIn('given_name', id_token)
            else:
                self.assertNotIn('given_name', id_token)

    def test_refresh_token(self):
        """
        A request to the Token Endpoint can also use a Refresh Token
        by using the grant_type value refresh_token, as described in
        Section 6 of OAuth 2.0 [RFC6749].
        """
        self.do_refresh_token_check()

    def test_refresh_token_invalid_scope(self):
        """
        Extending scope in refresh token is not allowed.

        Try to get a refresh token with "profile" in the scope even
        though the original authorized scope in the authorization code
        request is only ['openid', 'email'].
        """
        self.do_refresh_token_check(scope=['openid', 'profile'])

    def test_refresh_token_narrowed_scope(self):
        """
        Narrowing scope in refresh token is allowed.

        Try to get a refresh token with just "openid" in the scope even
        though the original authorized scope in the authorization code
        request is ['openid', 'email'].
        """
        self.do_refresh_token_check(scope=['openid'])

    @override_settings(OIDC_IDTOKEN_INCLUDE_CLAIMS=True)
    def do_refresh_token_check(self, scope=None):
        SIGKEYS = self._get_keys()

        # Retrieve refresh token
        code = self._create_code()
        self.assertEqual(code.scope, ['openid', 'email'])
        post_data = self._auth_code_post_data(code=code.code)
        start_time = time.time()
        with patch('oidc_provider.lib.utils.token.time.time') as time_func:
            time_func.return_value = start_time
            response = self._post_request(post_data)

        response_dic1 = json.loads(response.content.decode('utf-8'))
        id_token1 = JWS().verify_compact(response_dic1['id_token'].encode('utf-8'), SIGKEYS)

        # Use refresh token to obtain new token
        post_data = self._refresh_token_post_data(
            response_dic1['refresh_token'], scope)
        with patch('oidc_provider.lib.utils.token.time.time') as time_func:
            time_func.return_value = start_time + 600
            response = self._post_request(post_data)

        response_dic2 = json.loads(response.content.decode('utf-8'))

        if scope and set(scope) - set(code.scope):  # too broad scope
            self.assertEqual(response.status_code, 400)  # Bad Request
            self.assertIn('error', response_dic2)
            self.assertEqual(response_dic2['error'], 'invalid_scope')
            return  # No more checks

        id_token2 = JWS().verify_compact(response_dic2['id_token'].encode('utf-8'), SIGKEYS)

        if scope and 'email' not in scope:  # narrowed scope The auth
            # The auth code request had email in scope, so it should be
            # in the first id token
            self.assertIn('email', id_token1)
            # but the refresh request had no email in scope
            self.assertNotIn('email', id_token2, 'email was not requested')

        self.assertNotEqual(response_dic1['id_token'], response_dic2['id_token'])
        self.assertNotEqual(response_dic1['access_token'], response_dic2['access_token'])
        self.assertNotEqual(response_dic1['refresh_token'], response_dic2['refresh_token'])

        # http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.12.2
        self.assertEqual(id_token1['iss'], id_token2['iss'])
        self.assertEqual(id_token1['sub'], id_token2['sub'])
        self.assertNotEqual(id_token1['iat'], id_token2['iat'])
        self.assertEqual(id_token1['iat'], int(start_time))
        self.assertEqual(id_token2['iat'], int(start_time + 600))
        self.assertEqual(id_token1['aud'], id_token2['aud'])
        self.assertEqual(id_token1['auth_time'], id_token2['auth_time'])
        self.assertEqual(id_token1.get('azp'), id_token2.get('azp'))

        # Refresh token can't be reused
        post_data = self._refresh_token_post_data(response_dic1['refresh_token'])
        response = self._post_request(post_data)
        self.assertIn('invalid_grant', response.content.decode('utf-8'))

        # Old access token is invalidated
        self.assertEqual(self._get_userinfo(response_dic1['access_token']).status_code, 401)
        self.assertEqual(self._get_userinfo(response_dic2['access_token']).status_code, 200)

        # Empty refresh token is invalid
        post_data = self._refresh_token_post_data('')
        response = self._post_request(post_data)
        self.assertIn('invalid_grant', response.content.decode('utf-8'))

        # No refresh token is invalid
        post_data = self._refresh_token_post_data('')
        del post_data['refresh_token']
        response = self._post_request(post_data)
        self.assertIn('invalid_grant', response.content.decode('utf-8'))

    def test_client_redirect_uri(self):
        """
        Validate that client redirect URIs exactly match registered
        URIs, and that unregistered URIs or URIs with query parameters are rejected.
        See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest and
        http://openid.net/specs/openid-connect-core-1_0.html#HybridTokenRequest.
        """
        code = self._create_code()
        post_data = self._auth_code_post_data(code=code.code)

        # Unregistered URI
        post_data['redirect_uri'] = 'http://invalid.example.org'

        response = self._post_request(post_data)
        self.assertIn('invalid_client', response.content.decode('utf-8'))

        # Registered URI, but with query string appended
        post_data['redirect_uri'] = self.client.default_redirect_uri + '?foo=bar'

        response = self._post_request(post_data)
        self.assertIn('invalid_client', response.content.decode('utf-8'))

        # Registered URI
        post_data['redirect_uri'] = self.client.default_redirect_uri

        response = self._post_request(post_data)
        self.assertNotIn('invalid_client', response.content.decode('utf-8'))

    def test_request_methods(self):
        """
        Client sends an HTTP POST request to the Token Endpoint. Other request
        methods MUST NOT be allowed.
        """
        url = reverse('oidc_provider:token')

        requests = [
            self.factory.get(url),
            self.factory.put(url),
            self.factory.delete(url),
        ]

        for request in requests:
            response = TokenView.as_view()(request)

            self.assertEqual(
                response.status_code, 405,
                msg=request.method + ' request does not return a 405 status.')

        request = self.factory.post(url)

        response = TokenView.as_view()(request)

        self.assertEqual(
            response.status_code, 400,
            msg=request.method + ' request does not return a 400 status.')

    def test_client_authentication(self):
        """
        The authorization server support including the
        client credentials in the request-body using the `client_id` and
        `client_secret`parameters.

        See: http://tools.ietf.org/html/rfc6749#section-2.3.1
        """
        code = self._create_code()

        # Test a valid request to the token endpoint.
        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        self.assertNotIn(
            'invalid_client',
            response.content.decode('utf-8'),
            msg='Client authentication fails using request-body credentials.')

        # Now, test with an invalid client_id.
        invalid_data = post_data.copy()
        invalid_data['client_id'] = self.client.client_id * 2  # Fake id.

        # Create another grant code.
        code = self._create_code()
        invalid_data['code'] = code.code

        response = self._post_request(invalid_data)

        self.assertIn(
            'invalid_client',
            response.content.decode('utf-8'),
            msg='Client authentication success with an invalid "client_id".')

        # Now, test using HTTP Basic Authentication method.
        basicauth_data = post_data.copy()

        # Create another grant code.
        code = self._create_code()
        basicauth_data['code'] = code.code

        del basicauth_data['client_id']
        del basicauth_data['client_secret']

        response = self._post_request(basicauth_data, self._password_grant_auth_header())
        response.content.decode('utf-8')

        self.assertNotIn(
            'invalid_client',
            response.content.decode('utf-8'),
            msg='Client authentication fails using HTTP Basic Auth.')

    def test_access_token_contains_nonce(self):
        """
        If present in the Authentication Request, Authorization Servers MUST
        include a nonce Claim in the ID Token with the Claim Value being the
        nonce value sent in the Authentication Request.
        If the client does not supply a nonce parameter, it SHOULD not be
        included in the `id_token`.

        See http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('nonce'), FAKE_NONCE)

        # Client does not supply a nonce parameter.
        code.nonce = ''
        code.save()

        response = self._post_request(post_data)
        response_dic = json.loads(response.content.decode('utf-8'))

        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('nonce'), None)

    def test_id_token_contains_at_hash(self):
        """
        If access_token is included, the id_token SHOULD contain an at_hash.
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertTrue(id_token.get('at_hash'))

    def test_idtoken_sign_validation(self):
        """
        We MUST validate the signature of the ID Token according to JWS
        using the algorithm specified in the alg Header Parameter of
        the JOSE Header.
        """
        SIGKEYS = self._get_keys()
        RSAKEYS = [k for k in SIGKEYS if k.kty == 'RSA']

        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)
        response_dic = json.loads(response.content.decode('utf-8'))

        JWS().verify_compact(response_dic['id_token'].encode('utf-8'), RSAKEYS)

    @override_settings(
        OIDC_IDTOKEN_SUB_GENERATOR='oidc_provider.tests.app.utils.fake_sub_generator')
    def test_custom_sub_generator(self):
        """
        Test custom function for setting OIDC_IDTOKEN_SUB_GENERATOR.
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('sub'), self.user.email)

    @override_settings(
        OIDC_IDTOKEN_PROCESSING_HOOK='oidc_provider.tests.app.utils.fake_idtoken_processing_hook')
    def test_additional_idtoken_processing_hook(self):
        """
        Test custom function for setting OIDC_IDTOKEN_PROCESSING_HOOK.
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('test_idtoken_processing_hook'), FAKE_RANDOM_STRING)
        self.assertEqual(id_token.get('test_idtoken_processing_hook_user_email'), self.user.email)

    @override_settings(
        OIDC_IDTOKEN_PROCESSING_HOOK=(
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook',
        )
    )
    def test_additional_idtoken_processing_hook_one_element_in_tuple(self):
        """
        Test custom function for setting OIDC_IDTOKEN_PROCESSING_HOOK.
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('test_idtoken_processing_hook'), FAKE_RANDOM_STRING)
        self.assertEqual(id_token.get('test_idtoken_processing_hook_user_email'), self.user.email)

    @override_settings(
        OIDC_IDTOKEN_PROCESSING_HOOK=[
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook',
        ]
    )
    def test_additional_idtoken_processing_hook_one_element_in_list(self):
        """
        Test custom function for setting OIDC_IDTOKEN_PROCESSING_HOOK.
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('test_idtoken_processing_hook'), FAKE_RANDOM_STRING)
        self.assertEqual(id_token.get('test_idtoken_processing_hook_user_email'), self.user.email)

    @override_settings(
        OIDC_IDTOKEN_PROCESSING_HOOK=[
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook',
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook2',
        ]
    )
    def test_additional_idtoken_processing_hook_two_elements_in_list(self):
        """
        Test custom function for setting OIDC_IDTOKEN_PROCESSING_HOOK.
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('test_idtoken_processing_hook'), FAKE_RANDOM_STRING)
        self.assertEqual(id_token.get('test_idtoken_processing_hook_user_email'), self.user.email)

        self.assertEqual(id_token.get('test_idtoken_processing_hook2'), FAKE_RANDOM_STRING)
        self.assertEqual(id_token.get('test_idtoken_processing_hook_user_email2'), self.user.email)

    @override_settings(
        OIDC_IDTOKEN_PROCESSING_HOOK=(
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook',
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook2',
        )
    )
    def test_additional_idtoken_processing_hook_two_elements_in_tuple(self):
        """
        Test custom function for setting OIDC_IDTOKEN_PROCESSING_HOOK.
        """
        code = self._create_code()

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()

        self.assertEqual(id_token.get('test_idtoken_processing_hook'), FAKE_RANDOM_STRING)
        self.assertEqual(id_token.get('test_idtoken_processing_hook_user_email'), self.user.email)

        self.assertEqual(id_token.get('test_idtoken_processing_hook2'), FAKE_RANDOM_STRING)
        self.assertEqual(id_token.get('test_idtoken_processing_hook_user_email2'), self.user.email)

    @override_settings(
        OIDC_IDTOKEN_PROCESSING_HOOK=(
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook3'))
    def test_additional_idtoken_processing_hook_scope_available(self):
        """
        Test scope is available in OIDC_IDTOKEN_PROCESSING_HOOK.
        """
        id_token = self._request_id_token_with_scope(
            ['openid', 'email', 'profile', 'dummy'])
        self.assertEqual(
            id_token.get('scope_of_token_passed_to_processing_hook'),
            ['openid', 'email', 'profile', 'dummy'])

    @override_settings(
        OIDC_IDTOKEN_PROCESSING_HOOK=(
                'oidc_provider.tests.app.utils.fake_idtoken_processing_hook4'))
    def test_additional_idtoken_processing_hook_kwargs(self):
        """
        Test correct kwargs are passed to OIDC_IDTOKEN_PROCESSING_HOOK.
        """
        id_token = self._request_id_token_with_scope(['openid', 'profile'])
        kwargs_passed = id_token.get('kwargs_passed_to_processing_hook')
        assert kwargs_passed
        self.assertTrue(kwargs_passed.get('token').startswith(
                        '<Token: Some Client -'))
        self.assertEqual(kwargs_passed.get('request'),
                         "<WSGIRequest: POST '/openid/token'>")
        self.assertEqual(set(kwargs_passed.keys()), {'token', 'request'})

    def _request_id_token_with_scope(self, scope):
        code = self._create_code(scope)

        post_data = self._auth_code_post_data(code=code.code)

        response = self._post_request(post_data)

        response_dic = json.loads(response.content.decode('utf-8'))
        id_token = JWT().unpack(response_dic['id_token'].encode('utf-8')).payload()
        return id_token

    def test_pkce_parameters(self):
        """
        Test Proof Key for Code Exchange by OAuth Public Clients.
        https://tools.ietf.org/html/rfc7636
        """
        code = create_code(user=self.user, client=self.client,
                           scope=['openid', 'email'], nonce=FAKE_NONCE, is_authentication=True,
                           code_challenge=FAKE_CODE_CHALLENGE, code_challenge_method='S256')
        code.save()

        post_data = self._auth_code_post_data(code=code.code)

        # Add parameters.
        post_data['code_verifier'] = FAKE_CODE_VERIFIER

        response = self._post_request(post_data)

        json.loads(response.content.decode('utf-8'))

    @override_settings(OIDC_INTROSPECTION_VALIDATE_AUDIENCE_SCOPE=False)
    def test_client_credentials_grant_type(self):
        fake_scopes_list = ['scopeone', 'scopetwo', INTROSPECTION_SCOPE]

        # Add scope for this client.
        self.client.scope = fake_scopes_list
        self.client.save()

        post_data = {
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret,
            'grant_type': 'client_credentials',
        }
        response = self._post_request(post_data)
        response_dict = json.loads(response.content.decode('utf-8'))

        # Ensure access token exists in the response, also check if scopes are
        # the ones we registered previously.
        self.assertTrue('access_token' in response_dict)
        self.assertEqual(' '.join(fake_scopes_list), response_dict['scope'])

        access_token = response_dict['access_token']

        # Create a protected resource and test the access_token.

        @require_http_methods(['GET'])
        @protected_resource_view(fake_scopes_list)
        def protected_api(request, *args, **kwargs):
            return JsonResponse({'protected': 'information'}, status=200)

        # Deploy view on some url. So, base url could be anything.
        request = self.factory.get(
            '/api/protected/?access_token={0}'.format(access_token))
        response = protected_api(request)
        response_dict = json.loads(response.content.decode('utf-8'))

        self.assertEqual(response.status_code, 200)
        self.assertTrue('protected' in response_dict)

        # Protected resource test ends here.

        # Verify access_token can be validated with token introspection

        response = self.request_client.post(
            reverse('oidc_provider:token-introspection'), data={'token': access_token},
            **self._password_grant_auth_header())
        self.assertEqual(response.status_code, 200)
        response_dict = json.loads(response.content.decode('utf-8'))
        self.assertTrue(response_dict.get('active'))

        # End token introspection test

        # Clean scopes for this client.
        self.client.scope = ''
        self.client.save()

        response = self._post_request(post_data)
        response_dict = json.loads(response.content.decode('utf-8'))

        # It should fail when client does not have any scope added.
        self.assertEqual(400, response.status_code)
        self.assertEqual('invalid_scope', response_dict['error'])

    def test_printing_token_used_by_client_credentials_grant_type(self):
        # Add scope for this client.
        self.client.scope = ['something']
        self.client.save()

        post_data = {
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret,
            'grant_type': 'client_credentials',
        }
        response = self._post_request(post_data)
        response_dict = json.loads(response.content.decode('utf-8'))
        token = Token.objects.get(access_token=response_dict['access_token'])
        self.assertTrue(str(token))
