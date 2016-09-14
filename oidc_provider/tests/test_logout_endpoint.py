from django.core.urlresolvers import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from jwkest.jwk import SYMKey
from jwkest.jws import JWS

from oidc_provider import settings
from oidc_provider.tests.app.utils import create_fake_user, create_fake_client

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


class UserInfoTestCase(TestCase):
    def setUp(self):
        user_password = 'password'

        self.user = create_fake_user(password=user_password)
        self.sub = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=self.user)
        self.client.login(username=self.user.username, password=user_password)

        self.rp_client = create_fake_client('code', jwt_alg='HS256')
        self.rp_keys = [SYMKey(key=self.rp_client.client_secret, alg=self.rp_client.jwt_alg)]

        self.logout_callback = 'http://testserver.com/logout_callback'

    def _request_logout(self, **kwargs):
        url = reverse('oidc_provider:logout')
        query_string = urlencode(kwargs)
        return self.client.get('%s?%s' % (url, query_string))

    def _token_signed_by_client(self, payload):
        return JWS(payload, alg=self.rp_client.jwt_alg).sign_compact(keys=self.rp_keys)

    def _token_unsigned(self, payload):
        return JWS(payload, alg=None).sign_compact(keys=None)

    def test_ok_on_missing_id_token_hint(self):
        response = self._request_logout()

        self.assertRedirects(response, expected_url=settings.get('LOGIN_URL'), fetch_redirect_response=False)
        self.assertIn('max-age=0', response['Cache-Control'])

    def test_bad_request_on_bad_syntax_token(self):
        response = self._request_logout(id_token_hint='some_token')

        self.assertBadRequest(response)

    def test_bad_request_on_client_missing(self):
        token = self._token_unsigned({'aud': '1'})

        response = self._request_logout(id_token_hint=token)

        self.assertBadRequest(response)

    def test_bad_request_on_bad_signature(self):
        token = self._token_signed_by_client({'aud': self.rp_client.client_id})

        response = self._request_logout(id_token_hint=token[:-1])

        self.assertBadRequest(response)

    def test_bad_request_on_authenticated_user_diff_from_sub(self):
        token = self._token_signed_by_client({'aud': self.rp_client.client_id})

        response = self._request_logout(id_token_hint=token)

        self.assertBadRequest(response)

    def test_ok_default_redirect(self):
        token = self._token_signed_by_client({'aud': self.rp_client.client_id, 'sub': self.sub})

        response = self._request_logout(id_token_hint=token)

        self.assertRedirects(response, expected_url=settings.get('LOGIN_URL'), fetch_redirect_response=False)
        self.assertIn('max-age=0', response['Cache-Control'])

    def test_bad_request_redirect_not_registered(self):
        token = self._token_signed_by_client({'aud': self.rp_client.client_id, 'sub': self.sub})

        response = self._request_logout(id_token_hint=token, post_logout_redirect_uri=self.logout_callback)

        self.assertBadRequest(response)

    def test_ok_redirect_to_client(self):
        token = self._token_signed_by_client({'aud': self.rp_client.client_id, 'sub': self.sub})

        self.rp_client.post_logout_redirect_uris = [self.logout_callback]
        self.rp_client.save()

        response = self._request_logout(id_token_hint=token, post_logout_redirect_uri=self.logout_callback)

        self.assertRedirects(response, expected_url=self.logout_callback, fetch_redirect_response=False)

    def test_ok_redirect_to_client_plus_state(self):
        token = self._token_signed_by_client({'aud': self.rp_client.client_id, 'sub': self.sub})

        self.rp_client.post_logout_redirect_uris = [self.logout_callback]
        self.rp_client.save()

        state = get_random_string()

        response = self._request_logout(id_token_hint=token, post_logout_redirect_uri=self.logout_callback,
                                        state=state)

        self.assertRedirects(response, expected_url='http://testserver.com/logout_callback?state=%s' % state,
                             fetch_redirect_response=False)

    def assertBadRequest(self, response):
        self.assertEqual(response.status_code, 400)
