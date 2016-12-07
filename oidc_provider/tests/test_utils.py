from django.test import TestCase

from oidc_provider.lib.utils.common import get_issuer


class Request(object):
    """
    Mock request object.
    """
    scheme = 'http'

    def get_host(self):
        return 'host-from-request:8888'


class CommonTest(TestCase):
    """
    Test cases for common utils.
    """
    def test_get_issuer(self):
        request = Request()

        # from default settings
        self.assertEqual(get_issuer(),
                         'http://localhost:8000/openid')

        # from custom settings
        with self.settings(SITE_URL='http://otherhost:8000'):
            self.assertEqual(get_issuer(),
                             'http://otherhost:8000/openid')

        # `SITE_URL` not set, from `request`
        with self.settings(SITE_URL=''):
            self.assertEqual(get_issuer(request=request),
                             'http://host-from-request:8888/openid')

        # use settings first if both are provided
        self.assertEqual(get_issuer(request=request),
                         'http://localhost:8000/openid')

        # `site_url` can even be overridden manually
        self.assertEqual(get_issuer(site_url='http://127.0.0.1:9000',
                                    request=request),
                         'http://127.0.0.1:9000/openid')
