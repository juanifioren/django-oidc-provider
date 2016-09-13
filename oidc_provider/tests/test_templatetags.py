from django.template import Context
from django.template import Template
from django.test import RequestFactory
from django.test import TestCase
from django.utils import timezone

from oidc_provider.models import Client, Token
from oidc_provider.tests.app.utils import create_fake_user


class LogoutClientsTagTest(TestCase):
    TEMPLATE = Template("{% load frontchannel_logout %}{% logout_clients %}")

    def setUp(self):
        self.user = create_fake_user()
        self.factory = RequestFactory()

        self.client_logout = Client.objects.create(client_id='1',
                                                   frontchannel_logout_uri='http://example.com/logout',
                                                   frontchannel_logout_session_supported=False)
        self.client_logout_session = Client.objects.create(client_id='2',
                                                           frontchannel_logout_uri='http://example2.com/logout',
                                                           frontchannel_logout_session_supported=True)
        self.client_no_logout = Client.objects.create(client_id='3')
        self.client_logout2 = Client.objects.create(client_id='4',
                                                    frontchannel_logout_uri='http://example4.com/logout',
                                                    frontchannel_logout_session_supported=False)

    def test_render_logout_clients_iframe(self):
        Token.objects.create(user=self.user,
                             client=self.client_logout,
                             access_token='token1',
                             expires_at=timezone.now())
        Token.objects.create(user=self.user,
                             client=self.client_logout_session,
                             access_token='token2',
                             expires_at=timezone.now())
        Token.objects.create(user=self.user,
                             client=self.client_no_logout,
                             access_token='token3',
                             expires_at=timezone.now())

        request = self.factory.get('/')
        request.user_logged_out = self.user

        context = Context({})
        context.request = request

        rendered = self.TEMPLATE.render(context)

        # User is logged at client1 and client2. Client3 does not support frontchannel logout.

        self.assertIn('iframe src="http://example.com/logout"', rendered)
        self.assertIn('iframe src="http://example2.com/logout?iss=http://localhost:8000/openid&sid=', rendered)
        self.assertNotIn('iframe src=""', rendered)
        self.assertNotIn('iframe src="http://example4.com/logout"', rendered)
