from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils.six import StringIO


class CreateRSAKeyTest(TestCase):

    @override_settings(BASE_DIR='/tmp')
    def test_command_output(self):
        out = StringIO()
        call_command('creatersakey', stdout=out)
        self.assertIn('RSA key successfully created', out.getvalue())
