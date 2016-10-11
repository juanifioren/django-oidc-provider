from datetime import timedelta
import json
import uuid

from base64 import b64encode
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

from django.core.management import call_command
from django.core.urlresolvers import reverse
from django.test import (
    RequestFactory,
    override_settings,
)
from django.test import TestCase
from django.utils import timezone
from jwkest.jwk import KEYS
from jwkest.jws import JWS
from jwkest.jwt import JWT
from mock import patch

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
        self.client = create_fake_client(response_type='code')

    def _auth_code_post_data(self, code):
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

        return post_data

    def _refresh_token_post_data(self, refresh_token):
        """
        All the data that will be POSTed to the Token Endpoint.
        """
        post_data = {
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        return post_data

    def _post_request(self, post_data, extras={}):
        """
        Makes a request to the token endpoint by sending the
        `post_data` parameters using the 'application/x-www-form-urlencoded'
        format.
        """
        url = reverse('oidc_provider:token')

        request = self.factory.post(url,
            data=urlencode(post_data),
            content_type='application/x-www-form-urlencoded',
            **extras)

        response = TokenView.as_view()(request)

        return response

    def _create_code(self):
        """
        Generate a valid grant code.
        """
        code = create_code(
            user=self.user,
            client=self.client,
            scope=['openid', 'email'],
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
        self.assertEqual(id_token['aud'], self.client.client_id);

    def test_refresh_token(self):
        """
        A request to the Token Endpoint can also use a Refresh Token
        by using the grant_type value refresh_token, as described in
        Section 6 of OAuth 2.0 [RFC6749].
        """
        SIGKEYS = self._get_keys()

        # Retrieve refresh token
        code = self._create_code()
        post_data = self._auth_code_post_data(code=code.code)
        real_now = timezone.now
        with patch('oidc_provider.lib.utils.token.timezone.now') as now:
            now.return_value = real_now()
            response = self._post_request(post_data)

        response_dic1 = json.loads(response.content.decode('utf-8'))
        id_token1 = JWS().verify_compact(response_dic1['id_token'].encode('utf-8'), SIGKEYS)

        # Use refresh token to obtain new token
        post_data = self._refresh_token_post_data(response_dic1['refresh_token'])
        with patch('oidc_provider.lib.utils.token.timezone.now') as now:
            now.return_value = real_now() + timedelta(minutes=10)
            response = self._post_request(post_data)

        response_dic2 = json.loads(response.content.decode('utf-8'))
        id_token2 = JWS().verify_compact(response_dic2['id_token'].encode('utf-8'), SIGKEYS)

        self.assertNotEqual(response_dic1['id_token'], response_dic2['id_token'])
        self.assertNotEqual(response_dic1['access_token'], response_dic2['access_token'])
        self.assertNotEqual(response_dic1['refresh_token'], response_dic2['refresh_token'])

        # http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.12.2
        self.assertEqual(id_token1['iss'], id_token2['iss'])
        self.assertEqual(id_token1['sub'], id_token2['sub'])
        self.assertNotEqual(id_token1['iat'], id_token2['iat'])
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

    def test_client_redirect_url(self):
        """
        Validate that client redirect URIs with query strings match registered
        URIs, and that unregistered URIs are rejected.

        source: https://github.com/jerrykan/django-oidc-provider/blob/2f54e537666c689dd8448f8bbc6a3a0244b01a97/oidc_provider/tests/test_token_endpoint.py
        """
        SIGKEYS = self._get_keys()
        code = self._create_code()
        post_data = self._auth_code_post_data(code=code.code)

        # Unregistered URI
        post_data['redirect_uri'] = 'http://invalid.example.org'

        response = self._post_request(post_data)

        self.assertIn('invalid_client', response.content.decode('utf-8')),

        # Registered URI contained a query string
        post_data['redirect_uri'] = 'http://example.com/?client=OidcClient'

        response = self._post_request(post_data)

        self.assertNotIn('invalid_client', response.content.decode('utf-8')),

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

            self.assertEqual(response.status_code == 405, True,
                msg=request.method + ' request does not return a 405 status.')

        request = self.factory.post(url)

        response = TokenView.as_view()(request)

        self.assertEqual(response.status_code == 400, True,
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

        self.assertEqual('invalid_client' in response.content.decode('utf-8'),
                False,
                msg='Client authentication fails using request-body credentials.')

        # Now, test with an invalid client_id.
        invalid_data = post_data.copy()
        invalid_data['client_id'] = self.client.client_id * 2  # Fake id.

        # Create another grant code.
        code = self._create_code()
        invalid_data['code'] = code.code

        response = self._post_request(invalid_data)

        self.assertEqual('invalid_client' in response.content.decode('utf-8'),
                True,
                msg='Client authentication success with an invalid "client_id".')

        # Now, test using HTTP Basic Authentication method.
        basicauth_data = post_data.copy()

        # Create another grant code.
        code = self._create_code()
        basicauth_data['code'] = code.code

        del basicauth_data['client_id']
        del basicauth_data['client_secret']

        # Generate HTTP Basic Auth header with id and secret.
        user_pass = self.client.client_id + ':' + self.client.client_secret
        auth_header = b'Basic ' + b64encode(user_pass.encode('utf-8'))
        response = self._post_request(basicauth_data, {
            'HTTP_AUTHORIZATION': auth_header.decode('utf-8'),
        })
        response.content.decode('utf-8')

        self.assertEqual('invalid_client' in response.content.decode('utf-8'),
                False,
                msg='Client authentication fails using HTTP Basic Auth.')

    def test_client_redirect_url(self):
        """
        Validate that client redirect URIs with query strings match registered
        URIs, and that unregistered URIs are rejected.
        """
        SIGKEYS = self._get_keys()
        code = self._create_code()
        post_data = self._auth_code_post_data(code=code.code)

        # Unregistered URI
        post_data['redirect_uri'] = 'http://invalid.example.org'

        response = self._post_request(post_data)

        self.assertIn('invalid_client', response.content.decode('utf-8')),

        # Registered URI contained a query string
        post_data['redirect_uri'] = 'http://example.com/?client=OidcClient'

        response = self._post_request(post_data)

        self.assertNotIn('invalid_client', response.content.decode('utf-8')),

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

        id_token = JWS().verify_compact(response_dic['id_token'].encode('utf-8'), RSAKEYS)

    @override_settings(OIDC_IDTOKEN_SUB_GENERATOR='oidc_provider.tests.app.utils.fake_sub_generator')
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

    @override_settings(OIDC_IDTOKEN_PROCESSING_HOOK='oidc_provider.tests.app.utils.fake_idtoken_processing_hook')
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

        response_dic = json.loads(response.content.decode('utf-8'))
