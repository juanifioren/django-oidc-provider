import time
from datetime import date
from datetime import datetime
from hashlib import sha224
from unittest.mock import Mock

from django.http import HttpRequest
from django.test import TestCase
from django.test import override_settings
from django.utils import timezone

from oidc_provider.lib.utils.common import get_browser_state_or_default
from oidc_provider.lib.utils.common import get_issuer
from oidc_provider.lib.utils.sanitization import sanitize_client_id
from oidc_provider.lib.utils.token import create_id_token
from oidc_provider.lib.utils.token import create_token
from oidc_provider.tests.app.utils import create_fake_client
from oidc_provider.tests.app.utils import create_fake_user


class Request(object):
    """
    Mock request object.
    """

    scheme = "http"

    def get_host(self):
        return "host-from-request:8888"


class CommonTest(TestCase):
    """
    Test cases for common utils.
    """

    def test_get_issuer(self):
        request = Request()

        # from default settings
        self.assertEqual(get_issuer(), "http://localhost:8000/openid")

        # from custom settings
        with self.settings(SITE_URL="http://otherhost:8000"):
            self.assertEqual(get_issuer(), "http://otherhost:8000/openid")

        # `SITE_URL` not set, from `request`
        with self.settings(SITE_URL=""):
            self.assertEqual(get_issuer(request=request), "http://host-from-request:8888/openid")

        # use settings first if both are provided
        self.assertEqual(get_issuer(request=request), "http://localhost:8000/openid")

        # `site_url` can even be overridden manually
        self.assertEqual(
            get_issuer(site_url="http://127.0.0.1:9000", request=request),
            "http://127.0.0.1:9000/openid",
        )


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
        id_token_data = create_id_token(token=token, user=self.user, aud="test-aud")
        iat = id_token_data["iat"]
        self.assertEqual(type(iat), int)
        self.assertGreaterEqual(iat, start_time)
        self.assertLessEqual(iat - start_time, 5)  # Can't take more than 5 s
        self.assertEqual(
            id_token_data,
            {
                "aud": "test-aud",
                "auth_time": login_timestamp,
                "exp": iat + 600,
                "iat": iat,
                "iss": "http://localhost:8000/openid",
                "sub": str(self.user.id),
            },
        )

    @override_settings(OIDC_IDTOKEN_INCLUDE_CLAIMS=True)
    def test_create_id_token_with_include_claims_setting(self):
        client = create_fake_client("code")
        token = create_token(self.user, client, scope=["openid", "email"])
        id_token_data = create_id_token(token=token, user=self.user, aud="test-aud")
        self.assertIn("email", id_token_data)
        self.assertTrue(id_token_data["email"])
        self.assertIn("email_verified", id_token_data)
        self.assertTrue(id_token_data["email_verified"])

    @override_settings(
        OIDC_IDTOKEN_INCLUDE_CLAIMS=True,
        OIDC_EXTRA_SCOPE_CLAIMS="oidc_provider.tests.app.utils.FakeScopeClaims",
    )
    def test_create_id_token_with_include_claims_setting_and_extra(self):
        client = create_fake_client("code")
        token = create_token(self.user, client, scope=["openid", "email", "pizza"])
        id_token_data = create_id_token(token=token, user=self.user, aud="test-aud")
        # Standard claims included.
        self.assertIn("email", id_token_data)
        self.assertTrue(id_token_data["email"])
        self.assertIn("email_verified", id_token_data)
        self.assertTrue(id_token_data["email_verified"])
        # Extra claims included.
        self.assertIn("pizza", id_token_data)
        self.assertEqual(id_token_data["pizza"], "Margherita")

    def test_token_saving_id_token_with_non_serialized_objects(self):
        client = create_fake_client("code")
        token = create_token(self.user, client, scope=["openid", "email", "pizza"])
        token.id_token = {
            "iss": "http://localhost:8000/openid",
            "sub": "1",
            "aud": "test-aud",
            "exp": 1733946683,
            "iat": 1733946083,
            "auth_time": 1733946082,
            "email": "johndoe@example.com",
            "email_verified": True,
            "_extra_datetime": datetime(2002, 10, 15, 9),
            "_extra_date": date(2000, 12, 25),
            "_extra_object": object,
        }
        token.save()

        # A raw datetime/date object should be serialized.
        self.assertEqual(token.id_token["_extra_datetime"], "2002-10-15 09:00:00")
        self.assertEqual(token.id_token["_extra_date"], "2000-12-25")
        # Even a raw object should be serialized wit str() at least.
        self.assertEqual(token.id_token["_extra_object"], "<class 'object'>")


class BrowserStateTest(TestCase):
    @override_settings(OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY="my_static_key")
    def test_get_browser_state_uses_value_from_settings_to_calculate_browser_state(self):
        request = HttpRequest()
        request.session = Mock(session_key=None)
        state = get_browser_state_or_default(request)
        self.assertEqual(state, sha224("my_static_key".encode("utf-8")).hexdigest())

    def test_get_browser_state_uses_session_key_to_calculate_browser_state_if_available(self):
        request = HttpRequest()
        request.session = Mock(session_key="my_session_key")
        state = get_browser_state_or_default(request)
        self.assertEqual(state, sha224("my_session_key".encode("utf-8")).hexdigest())


class SanitizationTest(TestCase):
    """
    Test cases for sanitization utils.
    """

    def test_sanitize_client_id_removes_null_bytes(self):
        """Test that null bytes are removed from client_id."""
        client_id = "Hello\x00World"
        result = sanitize_client_id(client_id)
        self.assertEqual(result, "HelloWorld")

    def test_sanitize_client_id_removes_control_characters(self):
        """Test that various control characters are removed."""
        client_id = "client\x01\x02\x03\x1f\x7fid"
        result = sanitize_client_id(client_id)
        self.assertEqual(result, "clientid")

    def test_sanitize_client_id_preserves_valid_characters(self):
        """Test that valid visible ASCII characters are preserved."""
        client_id = "valid-client_123.abc!@#$%^&*()+={}[]|\\:;\"'<>?,./~`"
        result = sanitize_client_id(client_id)
        self.assertEqual(result, client_id)  # Should remain unchanged

    def test_sanitize_client_id_handles_empty_string(self):
        """Test that empty string returns empty string."""
        result = sanitize_client_id("")
        self.assertEqual(result, "")

    def test_sanitize_client_id_handles_none(self):
        """Test that None returns empty string."""
        result = sanitize_client_id(None)
        self.assertEqual(result, "")

    def test_sanitize_client_id_removes_whitespace_characters(self):
        """Test that whitespace characters are removed (not part of VCHAR)."""
        client_id = "client\t\n\r id"
        result = sanitize_client_id(client_id)
        self.assertEqual(result, "clientid")

    def test_sanitize_client_id_preserves_printable_ascii(self):
        """Test preservation of all printable ASCII characters (0x21-0x7E)."""
        # All VCHAR characters as per RFC 6749
        vchar_string = "".join(chr(i) for i in range(0x21, 0x7F))
        result = sanitize_client_id(vchar_string)
        self.assertEqual(result, vchar_string)

    def test_sanitize_client_id_removes_unicode_characters(self):
        """Test that Unicode characters outside ASCII range are removed."""
        client_id = "client-ñáéíóú-测试-🔥"
        result = sanitize_client_id(client_id)
        self.assertEqual(result, "client---")

    def test_sanitize_client_id_mixed_valid_invalid(self):
        """Test mixed valid and invalid characters."""
        client_id = "valid\x00client\x01-\x7f123\tabc"
        result = sanitize_client_id(client_id)
        self.assertEqual(result, "validclient-123abc")
