import time
from datetime import datetime

from django.test import TestCase
from django.utils import timezone

from oidc_provider.lib.utils.common import get_issuer
from oidc_provider.lib.utils.token import create_id_token
from oidc_provider.tests.app.utils import create_fake_user
from django.test import override_settings


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


def timestamp_to_datetime(timestamp):
    tz = timezone.get_current_timezone()
    return datetime.fromtimestamp(timestamp, tz=tz)


class TokenTest(TestCase):
    def setUp(self):
        self.user = create_fake_user()

    @override_settings(OIDC_IDTOKEN_EXPIRE=600)
    def test_create_id_token(self):
        start_time = int(time.time())
        login_timestamp = start_time - 1234
        self.user.last_login = timestamp_to_datetime(login_timestamp)
        id_token_data = create_id_token(self.user, aud='test-aud')
        iat = id_token_data['iat']
        self.assertEqual(type(iat), int)
        self.assertGreaterEqual(iat, start_time)
        self.assertLessEqual(iat - start_time, 5)  # Can't take more than 5 s
        self.assertEqual(id_token_data, {
            'aud': 'test-aud',
            'auth_time': login_timestamp,
            'exp': iat + 600,
            'iat': iat,
            'iss': 'http://localhost:8000/openid',
            'sub': str(self.user.id),
        })
