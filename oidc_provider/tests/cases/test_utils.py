import time
from datetime import datetime
from hashlib import sha224

from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.utils import timezone
from mock import mock

from oidc_provider.lib.utils.common import get_issuer, get_browser_state_or_default
from oidc_provider.lib.utils.token import (
    create_token, create_id_token, get_by_access_token, get_by_refresh_token)
from oidc_provider.tests.app.utils import create_fake_user, create_fake_client
from oidc_provider.models import Token


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
        client = create_fake_client("code")
        token = create_token(self.user, client, [], request=None)
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

    def test_get_token_using_hash(self):
        client1 = create_fake_client("code")
        client2 = create_fake_client("code")
        token1 = create_token(self.user, client1, [], request=None)

        # can get tokens
        self.assertEqual(token1, get_by_access_token(token1.access_token))
        self.assertEqual(token1, get_by_refresh_token(token1.refresh_token))

        # get tokens filtered by client
        self.assertEqual(token1, get_by_access_token(token1.access_token, client=client1))
        self.assertEqual(token1, get_by_refresh_token(token1.refresh_token, client=client1))

        # can't get tokens if client does not match
        self.assertRaises(
            Token.DoesNotExist,
            get_by_access_token,
            token1.access_token,
            client=client2,
        )
        self.assertRaises(
            Token.DoesNotExist,
            get_by_refresh_token,
            token1.refresh_token,
            client=client2,
        )


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
