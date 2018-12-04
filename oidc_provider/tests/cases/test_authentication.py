import time
from unittest.mock import patch, PropertyMock, Mock
from datetime import datetime
from django.conf import settings
from collections import namedtuple
from django.test import override_settings
from rest_framework.exceptions import AuthenticationFailed
from oidc_provider.authentication import BearerTokenAuthentication, JSONWebTokenAuthentication
from oidc_provider.client import fetch_service_token


class BearerTokenAuthenticationTestCase(BaseTestCase):

    def setUp(self):
        self.active = True
        patch_config = patch(
            'oidc_provider.authentication.BearerTokenAuthentication.oidc_config',
            new_callable=PropertyMock(return_value={
                'introspection_endpoint': 'introspection-endpoint-url'}))
        patch_introspect = patch('oidc_provider.authentication.requests.post', side_effect=self.mocked_introspect_post)

        patch_header = patch(
            'oidc_provider.authentication.get_authorization_header',
            return_value='Bearer some-token'.encode('ascii'))
        cache_mock = Mock()
        cache_mock.get.return_value = None
        patch_dj_cache = patch('oidc_provider.util.dj_cache', new=cache_mock)

        patch_dj_cache.start()
        patch_config.start()
        patch_introspect.start()
        patch_header.start()

        self.addCleanup(patch_dj_cache.stop)
        self.addCleanup(patch_header.stop)
        self.addCleanup(patch_introspect.stop)
        self.addCleanup(patch_config.stop)

    def get_response(self):
        return {
            "aud": "http://oidc-service.com/resources",
            "iss": "http://oidc-service.com",
            "nbf": int(time.time()) - 1000,
            "exp": int(time.time()) + 1000,
            "client_id": "paw-frontend",
            "role": [
                "service-directory-reader",
                "service-directory-writer"
            ],
            "active": self.active,
            "scope": "paw-service"
        }

    def mocked_introspect_post(self, *args, **kwargs):
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        # requested URL needs to much mocked oidc config to give the JSON response
        if args[0] == 'introspection-endpoint-url':
            return MockResponse(self.get_response(), 200)

        return MockResponse(None, 404)

    def test_valid_token(self):
        auth = BearerTokenAuthentication()
        user, authenticated = auth.authenticate({})
        self.assertTrue(authenticated)
        self.assertEqual(user.token, {})

    def test_inactive_token(self):
        self.active = False

        auth = BearerTokenAuthentication()
        with self.assertRaises(AuthenticationFailed):
            auth.authenticate({})

    @override_settings(OIDC_AUTH={**settings.OIDC_AUTH, **{'OIDC_SCOPE': 'missing'}})
    def test_bad_scope(self):
        auth = BearerTokenAuthentication()
        with self.assertRaises(AuthenticationFailed):
            auth.authenticate({})

    def test_invalid_header(self):
        # Two spaces, must only have one
        with patch('oidc_provider.authentication.get_authorization_header', return_value='Bearer bad token'.encode('ascii')):
            auth = BearerTokenAuthentication()
            with self.assertRaises(AuthenticationFailed):
                auth.authenticate({})
        # No spaces at all
        with patch('oidc_provider.authentication.get_authorization_header', return_value='Bearer'.encode('ascii')):
            auth = BearerTokenAuthentication()
            with self.assertRaises(AuthenticationFailed):
                auth.authenticate({})

        # JWT token
        with patch('oidc_provider.authentication.get_authorization_header', return_value='Bearer some.jwt.token'.encode('ascii')):
            auth = BearerTokenAuthentication()
            self.assertEqual(auth.authenticate({}), None)


@override_settings(OIDC_AUTH={**settings.OIDC_AUTH, **{'OIDC_AUDIENCES': 'http://oidc-service.com/resources'}})
class JWTAuthenticationTestCase(BaseTestCase):

    def setUp(self):
        super().setUp()
        patch_header = patch(
            'oidc_provider.authentication.get_authorization_header',
            return_value='Bearer ..some-token')
        patch_get_aud = patch('oidc_provider.authentication.JSONWebTokenAuthentication.get_audiences', return_value='http://oidc-service.com/resources')
        patch_decode_jwt = patch('oidc_provider.authentication.JSONWebTokenAuthentication.decode_jwt', return_value=self.get_token())
        patch_config = patch(
            'oidc_provider.authentication.JSONWebTokenAuthentication.oidc_config',
            new_callable=PropertyMock(return_value={
                'issuer': 'http://oidc-service.com'}))

        patch_get_aud.start()
        patch_header.start()
        patch_config.start()
        patch_decode_jwt.start()

        self.addCleanup(patch_get_aud.stop)
        self.addCleanup(patch_header.stop)
        self.addCleanup(patch_decode_jwt.stop)
        self.addCleanup(patch_config.stop)

    def get_token(self):
        return {
            'aud': ['http://oidc-service.com/resources'],
            'iss': 'http://oidc-service.com',
            'nbf': int(time.time()) - 1000,
            'exp': int(time.time()) + 1000,
            'client_id': 'paw-frontend',
            'role': [
                'service-directory-reader',
                'service-directory-writer'],
            'scope': [
                'openid',
                'paw-service'
            ]
        }

    def test_valid_token(self):
        auth = JSONWebTokenAuthentication()
        user, authenticated = auth.authenticate({})
        self.assertTrue(authenticated)

    @patch('oidc_provider.authentication.get_authorization_header', return_value='Bearer some-token')
    def test_bad_header_prefix(self, mock_header):
        result = JSONWebTokenAuthentication().authenticate(None)
        self.assertEqual(result, None)

    @patch('oidc_provider.authentication.get_authorization_header', return_value='Bearer onle.onedot')
    def test_bad_JWT_format(self, mock_header):
        result = JSONWebTokenAuthentication().authenticate(None)
        self.assertEqual(result, None)

    def test_invalid_header(self):
        # Two spaces, must only have one
        with patch('oidc_provider.authentication.get_authorization_header', return_value='Bearer bad token'):
                auth = JSONWebTokenAuthentication()
                with self.assertRaises(AuthenticationFailed):
                    auth.authenticate(None)
        # No spaces at all
        with patch('oidc_provider.authentication.get_authorization_header', return_value='Bearer'):
                auth = JSONWebTokenAuthentication()
                with self.assertRaises(AuthenticationFailed):
                    auth.authenticate(None)

    @patch('oidc_provider.authentication.JSONWebTokenAuthentication.get_audiences', return_value='wrong-aud')
    def test_validate_claims_audience(self, mock_aud):
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.authenticate(None)

        self.assertIn('Invalid JWT audience', str(error.exception))

    @patch('oidc_provider.authentication.JSONWebTokenAuthentication.oidc_config', new_callable=PropertyMock(return_value={'issuer': 'wrong'}))
    def test_validate_claims_issuer(self, config_patch):
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.authenticate(None)

        self.assertIn('Invalid JWT issuer', str(error.exception))

    def test_validate_authorized_party_missing(self):
        token = self.get_token()
        token['aud'] += ['second-audience']
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.validate_claims(token)

        self.assertIn('Missing JWT authorized party', str(error.exception))

    def test_validate_authorized_party_invalid(self):
        token = self.get_token()
        token['azp'] = 'authorized-party'
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.validate_claims(token)

        self.assertIn('Invalid JWT authorized party', str(error.exception))

    def test_expired_token(self):
        token = self.get_token()
        token['exp'] = token['nbf']
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.validate_claims(token)

        self.assertIn('JWT has expired', str(error.exception))

    def test_not_yet_valid_token(self):
        token = self.get_token()
        token['nbf'] = token['exp']
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.validate_claims(token)

        self.assertIn('JWT not yet valid', str(error.exception))

    @override_settings(OIDC_AUTH={**settings.OIDC_AUTH, **{'OIDC_LEEWAY': 500}})
    def test_token_too_old(self):
        token = self.get_token()
        token['iat'] = token['nbf']
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.validate_claims(token)

        self.assertIn('JWT too old', str(error.exception))

    @override_settings(OIDC_AUTH={**settings.OIDC_AUTH, **{'OIDC_LEEWAY': 2500}})
    def test_token_iat_valid(self):
        token = self.get_token()
        token['iat'] = token['nbf']
        auth = JSONWebTokenAuthentication()
        self.assertEqual(auth.validate_claims(token), None)

    @override_settings(OIDC_AUTH={**settings.OIDC_AUTH, **{'OIDC_SCOPE': 'bad-scope'}})
    def test_token_scope(self):
        token = self.get_token()
        auth = JSONWebTokenAuthentication()
        with self.assertRaises(AuthenticationFailed) as error:
            auth.validate_claims(token)

        self.assertIn('Invalid JWT scope', str(error.exception))


class FetchServiceTokenTestCase(BaseTestCase):

    @patch('oidc_provider.client.BackendApplicationClient')
    @patch('oidc_provider.client.OAuth2Session')
    def test_fetch_service_token(self, mock_session, mock_client):
        mock_session.return_value.fetch_token.return_value = 'fake-token'
        token = fetch_service_token('fake-claims')
        self.assertEqual(token, 'fake-token')
        mock_session.return_value.fetch_token.assert_called()
