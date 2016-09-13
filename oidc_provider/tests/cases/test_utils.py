import time
from datetime import datetime
from hashlib import sha224

from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.utils import timezone
from mock import mock

from oidc_provider.lib.utils.common import get_issuer, get_browser_state_or_default, get_user_sid
from oidc_provider.models import Client, Token

from oidc_provider.lib.utils.token import create_token, create_id_token
from oidc_provider.lib.utils.user import get_authorized_clients
from oidc_provider.tests.app.utils import create_fake_user, create_fake_client


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
        user1.last_login = timezone.datetime(year=2000, month=1, day=1)

        self.assertEqual('2b2b9cff7e1eb739f158a59f98daa0fdbe6f43a66b6f51892f639d72', get_user_sid(user1))

        # same date as user1, should generate a different sid
        user2 = create_fake_user(username='johndoe2')
        user2.last_login = timezone.datetime(year=2000, month=1, day=1)

        self.assertEqual('9225e0f32cea33183db63f5c7609e4d4a76e63bcfe0cd325ee775f4e', get_user_sid(user2))

        # change login date for user1
        user1.last_login = timezone.datetime(year=2020, month=1, day=1)

        self.assertEqual('42ca90ad794bf94ce23f56e03a46e0b24a6e5822a6c3f966066908f6', get_user_sid(user1))


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
        client = create_fake_client("code")
        token = create_token(self.user, client, [])
        id_token_data = create_id_token(token=token, user=self.user, aud='test-aud')
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


class BrowserStateTest(TestCase):

    @override_settings(OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY='my_static_key')
    def test_get_browser_state_uses_value_from_settings_to_calculate_browser_state(self):
        request = HttpRequest()
        request.session = mock.Mock(session_key=None)
        state = get_browser_state_or_default(request)
        self.assertEqual(state, sha224('my_static_key'.encode('utf-8')).hexdigest())

    def test_get_browser_state_uses_session_key_to_calculate_browser_state_if_available(self):
        request = HttpRequest()
        request.session = mock.Mock(session_key='my_session_key')
        state = get_browser_state_or_default(request)
        self.assertEqual(state, sha224('my_session_key'.encode('utf-8')).hexdigest())


class UserTest(TestCase):
    def setUp(self):
        self.user = create_fake_user()
        self.oidc_client = Client.objects.create(client_id='1')

    def test_get_authorized_clients(self):
        Token.objects.create(user=self.user,
                             client=self.oidc_client,
                             access_token='token1',
                             refresh_token='rtoken1',
                             expires_at=timezone.now())

        Token.objects.create(user=self.user,
                             client=self.oidc_client,
                             access_token='token2',
                             refresh_token='rtoken2',
                             expires_at=timezone.now())

        clients = get_authorized_clients(self.user)

        self.assertEqual(1, len(clients))

        client = next(iter(clients))
        self.assertTrue(isinstance(client, Client))
        self.assertEqual(self.oidc_client.pk, client.pk)
