from django.test import TestCase
from django.utils import timezone

from oidc_provider.lib.utils.common import get_issuer, get_user_sid
from oidc_provider.tests.app.utils import create_fake_user


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

    def test_get_user_sid(self):
        user1 = create_fake_user(username='johndoe')
        user1.last_login = timezone.datetime(year=2000,month=1,day=1)

        self.assertEqual('2b2b9cff7e1eb739f158a59f98daa0fdbe6f43a66b6f51892f639d72', get_user_sid(user1))

        # same date as user1, should generate a different sid
        user2 = create_fake_user(username='johndoe2')
        user2.last_login = timezone.datetime(year=2000, month=1, day=1)

        self.assertEqual('9225e0f32cea33183db63f5c7609e4d4a76e63bcfe0cd325ee775f4e', get_user_sid(user2))

        # change login date for user1
        user1.last_login = timezone.datetime(year=2020, month=1, day=1)

        self.assertEqual('42ca90ad794bf94ce23f56e03a46e0b24a6e5822a6c3f966066908f6', get_user_sid(user1))
