try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

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
        call_command("creatersakey")
        self.user = create_fake_user()
        self.client.force_login(self.user)

        # Create a client with a custom logout URL.
        self.oidc_client = create_fake_client("id_token")
        self.url_logout = "http://example.com/logged-out/"
        self.oidc_client.post_logout_redirect_uris = [self.url_logout]
        self.oidc_client.save()

        # Create a valid ID Token for the user.
        token = create_token(self.user, self.oidc_client, [])
        id_token_dic = create_id_token(token=token, user=self.user, aud=self.oidc_client.client_id)
        self.id_token = encode_id_token(id_token_dic, self.oidc_client)

        self.url = reverse("oidc_provider:end-session")
        self.url_prompt = reverse("oidc_provider:end-session-prompt")

    def test_id_token_hint_not_present_user_prompted(self):
        response = self.client.get(self.url)
        # We should display a logout consent prompt if id_token_hint parameter is not present.
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], self.url_prompt)
        # User still logged in.
        self.assertIn("_auth_user_id", self.client.session)

    @mock.patch("oidc_provider.views.after_end_session_hook")
    def test_id_token_hint_is_present_user_redirected_to_client_logout_url(
        self, after_end_session_hook
    ):
        query_params = {
            "id_token_hint": self.id_token,
        }
        response = self.client.get(self.url, query_params)
        # ID Token is valid so user was redirected to registered uri.
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], self.url_logout)
        # User logged out.
        self.assertNotIn("_auth_user_id", self.client.session)
        # End session hook should be called.
        self.assertTrue(after_end_session_hook.called)
        self.assertTrue(after_end_session_hook.call_count == 1)

    @mock.patch("oidc_provider.views.after_end_session_hook")
    def test_id_token_hint_is_present_user_redirected_to_client_logout_url_with_post(
        self, after_end_session_hook
    ):
        data = {
            "id_token_hint": self.id_token,
        }
        response = self.client.post(self.url, data)
        # ID Token is valid so user was
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], self.url_logout)
        # User logged out.
        self.assertNotIn("_auth_user_id", self.client.session)
        # End session hook should be called.
        self.assertTrue(after_end_session_hook.called)
        self.assertTrue(after_end_session_hook.call_count == 1)

    def test_state_is_present_and_being_passed_to_logout_url(self):
        query_params = {
            "id_token_hint": self.id_token,
            "state": "ABCDE",
        }
        response = self.client.get(self.url, query_params)
        # Let's ensure state is being passed to the logout url.
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"], "{0}?state={1}".format(self.url_logout, "ABCDE")
        )

    def test_post_logout_uri_not_in_client_urls(self):
        query_params = {
            "id_token_hint": self.id_token,
            "post_logout_redirect_uri": "http://other.com/bye/",
        }
        response = self.client.get(self.url, query_params)
        # We prompt the user since the post logout url is not from client urls.
        # Also ensure client_id is present since we could validate id_token_hint.
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"],
            "{0}?client_id={1}".format(self.url_prompt, self.oidc_client.client_id),
        )

    def test_prompt_view_redirecting_to_client_post_logout_since_user_unauthenticated(self):
        self.client.logout()
        query_params = {
            "client_id": self.oidc_client.client_id,
        }
        response = self.client.get(self.url_prompt, query_params)
        # Since user is unauthenticated on the backend, we send it back to client post logout
        # registered uri.
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], self.url_logout)

    def test_prompt_view_raising_404_since_user_unauthenticated_and_no_client(self):
        self.client.logout()
        response = self.client.get(self.url_prompt)
        # Since user is unauthenticated and no client information is present, we just show
        # not found page.
        self.assertEqual(response.status_code, 404)

    def test_prompt_view_displaying_logout_decision_form_to_user(self):
        query_params = {
            "client_id": self.oidc_client.client_id,
        }
        response = self.client.get(self.url_prompt, query_params)
        # User is prompted to logout with client information displayed.
        self.assertContains(
            response,
            "<p>Hi <strong>johndoe@example.com</strong>, are you sure you want to log out from <strong>Some Client</strong> app?</p>",  # noqa
            status_code=200,
            html=True,
        )

    def test_prompt_view_displaying_logout_decision_form_to_user_no_client(self):
        response = self.client.get(self.url_prompt)
        # User is prompted to logout without client information displayed.
        self.assertContains(
            response,
            "<p>Hi <strong>johndoe@example.com</strong>, are you sure you want to log out?</p>",
            status_code=200,
            html=True,
        )

    @mock.patch("oidc_provider.views.after_end_session_hook")
    def test_prompt_view_user_logged_out_after_form_allowed(self, after_end_session_hook):
        self.assertIn("_auth_user_id", self.client.session)
        # We want to POST to /end-session-prompt/?client_id=ABC endpoint.
        url_prompt_with_client = (
            self.url_prompt
            + "?"
            + urlencode(
                {
                    "client_id": self.oidc_client.client_id,
                }
            )
        )
        data = {
            "allow": "Anything",  # This means user allowed being logged out.
        }
        response = self.client.post(url_prompt_with_client, data)
        # Ensure user is now logged out and redirected to client post logout uri.
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], self.url_logout)
        # End session hook should be called.
        self.assertTrue(after_end_session_hook.called)
        self.assertTrue(after_end_session_hook.call_count == 1)

    @mock.patch("oidc_provider.views.after_end_session_hook")
    def test_prompt_view_user_logged_out_after_form_not_allowed(self, after_end_session_hook):
        self.assertIn("_auth_user_id", self.client.session)
        # We want to POST to /end-session-prompt/?client_id=ABC endpoint.
        url_prompt_with_client = (
            self.url_prompt
            + "?"
            + urlencode(
                {
                    "client_id": self.oidc_client.client_id,
                }
            )
        )
        response = self.client.post(url_prompt_with_client)  # No data.
        # Ensure user is still logged in and redirected to client post logout uri.
        self.assertIn("_auth_user_id", self.client.session)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], self.url_logout)
        # End session hook should not be called.
        self.assertFalse(after_end_session_hook.called)

    @mock.patch("oidc_provider.views.after_end_session_hook")
    def test_prompt_view_user_not_logged_out_after_form_not_allowed_no_client(
        self, after_end_session_hook
    ):
        self.assertIn("_auth_user_id", self.client.session)
        response = self.client.post(self.url_prompt)  # No data.
        # Ensure user is still logged in and 404 NOT FOUND was raised.
        self.assertIn("_auth_user_id", self.client.session)
        self.assertEqual(response.status_code, 404)
        # End session hook should not be called.
        self.assertFalse(after_end_session_hook.called)
