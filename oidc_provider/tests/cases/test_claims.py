from __future__ import unicode_literals

from django.test import TestCase
from django.utils.six import text_type
from django.utils.translation import override as override_language

from oidc_provider.lib.claims import ScopeClaims, StandardScopeClaims, STANDARD_CLAIMS
from oidc_provider.tests.app.utils import create_fake_user, create_fake_client, create_fake_token


class ClaimsTestCase(TestCase):

    def setUp(self):
        self.user = create_fake_user()
        self.scopes = ['openid', 'address', 'email', 'phone', 'profile', 'foo']
        self.client = create_fake_client('code')
        self.token = create_fake_token(self.user, self.scopes, self.client)
        self.scopeClaims = ScopeClaims(self.token)

    def test_empty_standard_claims(self):
        for v in [v for k, v in STANDARD_CLAIMS.items() if k != 'address']:
            self.assertEqual(v, '')

        for v in STANDARD_CLAIMS['address'].values():
            self.assertEqual(v, '')

    def test_clean_dic(self):
        """ assert that _clean_dic function returns a clean dictionnary
            (no empty claims) """
        dict_to_clean = {
            'phone_number_verified': '',
            'middle_name': '',
            'name': 'John Doe',
            'website': '',
            'profile': '',
            'family_name': 'Doe',
            'birthdate': '',
            'preferred_username': '',
            'picture': '',
            'zoneinfo': '',
            'locale': '',
            'gender': '',
            'updated_at': '',
            'address': {},
            'given_name': 'John',
            'email_verified': '',
            'nickname': '',
            'email': u'johndoe@example.com',
            'phone_number': '',
        }
        clean_dict = self.scopeClaims._clean_dic(dict_to_clean)
        self.assertEquals(
            clean_dict,
            {
                'family_name': 'Doe',
                'given_name': 'John',
                'name': 'John Doe',
                'email': u'johndoe@example.com'
            }
        )

    def test_locale(self):
        with override_language('fr'):
            self.assertEqual(text_type(StandardScopeClaims.info_profile[0]), 'Profil de base')

    def test_scopeclaims_class_inheritance(self):
        # Generate example class that will be used for `OIDC_EXTRA_SCOPE_CLAIMS` setting.
        class CustomScopeClaims(ScopeClaims):

            info_foo = ('Title', 'Description')

            def scope_foo(self):
                dic = {'test': self.user.id}
                return dic

            info_notadd = ('Title', 'Description')

            def scope_notadd(self):
                dic = {'test': self.user.id}
                return dic

        claims = CustomScopeClaims(self.token)
        response = claims.create_response_dic()

        self.assertTrue('test' in response.keys())
        self.assertFalse('notadd' in response.keys())
