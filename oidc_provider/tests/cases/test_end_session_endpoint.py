from django.core.management import call_command
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import TestCase

from oidc_provider.lib.utils.token import (
    create_token,
    create_id_token,
    encode_id_token,
)
from oidc_provider import settings
from oidc_provider.tests.app.utils import (
    create_fake_client,
    create_fake_user,
)
import mock


class EndSessionTestCase(TestCase):
    """
    See: http://openid.net/specs/openid-connect-session-1_0.html#RPLogout
    """

    def setUp(self):
        call_command('creatersakey')
        self.user = create_fake_user()

        self.oidc_client = create_fake_client('id_token')
        self.LOGOUT_URL = 'http://example.com/logged-out/'
        self.oidc_client.post_logout_redirect_uris = [self.LOGOUT_URL]
        self.oidc_client.save()

        self.url = reverse('oidc_provider:end-session')

    def test_redirects_when_aud_is_str(self):
        query_params = {
            'post_logout_redirect_uri': self.LOGOUT_URL,
        }
        response = self.client.get(self.url, query_params)
        # With no id_token the OP MUST NOT redirect to the requested
        # redirect_uri.
        self.assertRedirects(
            response, settings.get('OIDC_LOGIN_URL'),
            fetch_redirect_response=False)

        token = create_token(self.user, self.oidc_client, [])
        id_token_dic = create_id_token(
            token=token, user=self.user, aud=self.oidc_client.client_id)
        id_token = encode_id_token(id_token_dic, self.oidc_client)

        query_params['id_token_hint'] = id_token

        response = self.client.get(self.url, query_params)
        self.assertRedirects(
            response, self.LOGOUT_URL, fetch_redirect_response=False)

    def test_redirects_when_aud_is_list(self):
        """Check with 'aud' containing a list of str."""
        query_params = {
            'post_logout_redirect_uri': self.LOGOUT_URL,
        }
        token = create_token(self.user, self.oidc_client, [])
        id_token_dic = create_id_token(
            token=token, user=self.user, aud=self.oidc_client.client_id)
        id_token_dic['aud'] = [id_token_dic['aud']]
        id_token = encode_id_token(id_token_dic, self.oidc_client)
        query_params['id_token_hint'] = id_token
        response = self.client.get(self.url, query_params)
        self.assertRedirects(
            response, self.LOGOUT_URL, fetch_redirect_response=False)

    @mock.patch(settings.get('OIDC_AFTER_END_SESSION_HOOK'))
    def test_call_post_end_session_hook(self, hook_function):
        self.client.get(self.url)
        self.assertTrue(hook_function.called, 'OIDC_AFTER_END_SESSION_HOOK should be called')
        self.assertTrue(
            hook_function.call_count == 1,
            'OIDC_AFTER_END_SESSION_HOOK should be called once')
