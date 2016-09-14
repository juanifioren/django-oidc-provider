from django.http import HttpRequest
from django.test import TestCase

from oidc_provider.tests.app.utils import create_fake_user


class LogoutReceiverTestCase(TestCase):
    def setUp(self):
        user_password = 'password'
        self.user = create_fake_user(password=user_password)
        self.client.login(username=self.user.username, password=user_password)

    def test_logout_receiver_attaches_user_logged_out(self):
        # Logout based on Django's client.logout method.
        # Extended here to access the fake request.
        from django.contrib.auth import logout, get_user

        request = HttpRequest()
        request.session = self.client.session
        request.user = get_user(request)

        logout(request)

        self.assertFalse(request.user.is_authenticated())
        self.assertEqual(request.user_logged_out, self.user)
