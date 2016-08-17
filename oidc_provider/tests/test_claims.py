from django.test import TestCase
from oidc_provider.lib.claims import ScopeClaims
from oidc_provider.tests.app.utils import create_fake_user


class ClaimsTestCase(TestCase):

    def setUp(self):
        self.user = create_fake_user()
        self.scopes = ['openid', 'address', 'email', 'phone', 'profile']
        self.scopeClaims = ScopeClaims(self.user, self.scopes)

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
