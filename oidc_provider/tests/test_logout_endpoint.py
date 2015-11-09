from django.core.urlresolvers import reverse
from django.test import TestCase

from oidc_provider.views import *
from oidc_provider.tests.app.utils import *


class UserInfoTestCase(TestCase):

    def setUp(self):
        self.user = create_fake_user()
        self.url = reverse('oidc_provider:logout')

    def test_shows_logged_out_page(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'registration/logged_out.html')

    def test_redirects(self):
        response = self.client.get(self.url, data={'post_logout_redirect_uri': 'http://example.com/logged_out.html'})

        self.assertRedirects(response, 'http://example.com/logged_out.html',
                             fetch_redirect_response=False)

    def test_user_is_logged_out(self):
        self.assertTrue(self.client.login(username=self.user.username, password='1234'))
        self.assertGreater(len(self.client.session.keys()), 0)
        self.client.get(self.url)
        self.assertEqual(len(self.client.session.keys()), 0)
