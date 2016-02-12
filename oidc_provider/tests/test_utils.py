from django.conf import settings
from django.test import TestCase

from oidc_provider.lib.utils.common import get_issuer


class CommonTest(TestCase):
    """
    Test cases for common utils.
    """
    def test_get_issuer(self):
        issuer = get_issuer()
        self.assertEqual(issuer, settings.SITE_URL + '/openid')
