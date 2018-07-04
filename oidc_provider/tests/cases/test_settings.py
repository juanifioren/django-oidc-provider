from django.test import TestCase, override_settings

from oidc_provider import settings

CUSTOM_TEMPLATES = {
    'authorize': 'custom/authorize.html',
    'error': 'custom/error.html'
}


class SettingsTest(TestCase):

    @override_settings(OIDC_TEMPLATES=CUSTOM_TEMPLATES)
    def test_override_templates(self):
        self.assertEqual(settings.get('OIDC_TEMPLATES'), CUSTOM_TEMPLATES)

    def test_unauthenticated_session_management_key_has_default(self):
        key = settings.get('OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY')
        self.assertRegexpMatches(key, r'[a-zA-Z0-9]+')
        self.assertGreater(len(key), 50)

    def test_unauthenticated_session_management_key_has_constant_value(self):
        key1 = settings.get('OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY')
        key2 = settings.get('OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY')
        self.assertEqual(key1, key2)

    @override_settings(OIDC_INTROSPECTION_VALIDATE_AUDIENCE_SCOPE=False)
    def test_can_override_with_false_value(self):
        self.assertFalse(settings.get('OIDC_INTROSPECTION_VALIDATE_AUDIENCE_SCOPE'))
