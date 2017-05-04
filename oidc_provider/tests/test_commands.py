from django.core.management import call_command
from django.test import TestCase
from django.utils.six import StringIO


class CommandsTest(TestCase):

    def test_creatersakey_output(self):
        out = StringIO()
        call_command('creatersakey', stdout=out)
        self.assertIn('RSA key successfully created', out.getvalue())

    def test_makemigrations_output(self):
        out = StringIO()
        call_command('makemigrations', 'oidc_provider', stdout=out)
        self.assertIn('No changes detected in app', out.getvalue())

    def test_createrclientid_output(self):
        out = StringIO()
        call_command('createclientid', '--name=BrandNewClient', '--redirect-uris=http://domain.com/callback', stdout=out)
        self.assertIn('OAuth2 Client ID successfully created', out.getvalue())

    def test_createrclientid_redirect_uris_output(self):
        out = StringIO()
        call_command('createclientid', '--name=BrandNewClient', '--redirect-uris=http://domain.com/callback http://webhooks.domain.com/callback', stdout=out)
        self.assertIn('OAuth2 Client ID successfully created', out.getvalue())
        self.assertIn("['http://domain.com/callback',\n                   'http://webhooks.domain.com/callback']", out.getvalue())
