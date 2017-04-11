from django.test import TestCase, override_settings

from oidc_provider import settings

CUSTOM_TEMPLATES = {
    'authorize': 'custom/authorize.html',
    'error': 'custom/error.html'
}


class TokenTest(TestCase):

    @override_settings(OIDC_TEMPLATES=CUSTOM_TEMPLATES)
    def test_override_templates(self):
        self.assertEqual(settings.get('OIDC_TEMPLATES'), CUSTOM_TEMPLATES)
