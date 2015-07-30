from base64 import b64encode
import json
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
import uuid

from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase
from jwkest.jwk import KEYS
from jwkest.jws import JWS
from jwkest.jwt import JWT

from oidc_provider.lib.utils.token import *
from oidc_provider.tests.app.utils import *
from oidc_provider.views import *


class TokenTestCase(TestCase):
    """
    To obtain an Access Token and an ID Token, the RP Client sends a
    Token Request to the Token Endpoint to obtain a Token Response
    when using the Authorization Code Flow.
    """

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')

    def _post_data(self, code):
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
            nonce=FAKE_NONCE)
        code.save()

        return code

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
                msg=request.method+' request does not return a 405 status.')

        request = self.factory.post(url)

        response = TokenView.as_view()(request)

        self.assertEqual(response.status_code == 400, True,
                msg=request.method+' request does not return a 400 status.')

    def test_client_authentication(self):
        """
        The authorization server support including the
        client credentials in the request-body using the `client_id` and
        `client_secret`parameters.

        See: http://tools.ietf.org/html/rfc6749#section-2.3.1
        """
        code = self._create_code()

        # Test a valid request to the token endpoint.
        post_data = self._post_data(code=code.code)

        response = self._post_request(post_data)

        self.assertEqual('invalid_client' in response.content.decode('utf-8'),
                False,
                msg='Client authentication fails using request-body credentials.')

        # Now, test with an invalid client_id.
        invalid_data = post_data.copy()
        invalid_data['client_id'] = self.client.client_id * 2 # Fake id.

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

        post_data = self._post_data(code=code.code)

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

    def test_idtoken_sign_validation(self):
        """
        We MUST validate the signature of the ID Token according to JWS
        using the algorithm specified in the alg Header Parameter of
        the JOSE Header.
        """
        # Get public key from discovery.
        request = self.factory.get(reverse('oidc_provider:jwks'))
        response = JwksView.as_view()(request)
        jwks_dic = json.loads(response.content.decode('utf-8'))
        SIGKEYS = KEYS()
        SIGKEYS.load_dict(jwks_dic)
        RSAKEYS = [ k for k in SIGKEYS if k.kty == 'RSA' ]

        code = self._create_code()

        post_data = self._post_data(code=code.code)

        response = self._post_request(post_data)
        response_dic = json.loads(response.content.decode('utf-8'))

        id_token = JWS().verify_compact(response_dic['id_token'].encode('utf-8'), RSAKEYS)
