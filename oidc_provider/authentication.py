import requests
import time
import datetime
import six
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin
from requests.exceptions import HTTPError
from jwkest import JWKESTException
from jwkest.jwk import KEYS
from jwkest.jws import JWS
from django.utils.encoding import smart_text
from django.utils.functional import cached_property
from django.utils.translation import ugettext as _
from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from oidc_provider.util import cache


class AuthenticatedServiceClient:
    def __init__(self, token):
        self.token = token

    def is_authenticated(self):
        return True

    @staticmethod
    def create(payload):
        return AuthenticatedServiceClient(token)


class BaseOidcAuthentication(BaseAuthentication):

    @cached_property
    def oidc_config(self):
        url = urljoin(setttings.OIDC_ENDPOINT, '.well-known/openid-configuration')
        return requests.get(url).json()


class AccessTokenAuthentication(BaseOidcAuthentication):
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        bearer_token = self.get_bearer_token(request)
        if bearer_token is None:
            return None

        try:
            token_info = self.introspect_token(bearer_token)
        except HTTPError:
            msg = _('Invalid Authorization header. Unable to verify bearer token')
            raise AuthenticationFailed(msg)
        self.validate_bearer_token(token_info)

        return AuthenticatedServiceClient.create(token_info), True

    def validate_bearer_token(self, token_info):
        if token_info['active'] is False:
            msg = _('Authentication Failed. Received Inactive Token')
            raise AuthenticationFailed(msg)

        if setttings.OIDC_SCOPE not in token_info['scope']:
            msg = _('Authentication Failed. Invalid token scope')
            raise AuthenticationFailed(msg)

        utc_timestamp = int(time.time())
        if utc_timestamp > int(token_info.get('exp', 0)):
            msg = _('Authentication Failed. Token expired')
            raise AuthenticationFailed(msg)

    def get_bearer_token(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = setttings.BEARER_AUTH_HEADER_PREFIX.lower()

        if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
            return None
        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)
        elif smart_text(auth[1]).count('.') == 2:
            return None
        return auth[1]

    @cache(ttl=setttings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def introspect_token(self, token):
        response = requests.post(
            self.oidc_config['introspection_endpoint'],
            auth=HTTPBasicAuth(setttings.OIDC_INTERSPECT_USERNAME, setttings.OIDC_INTROSPECT_PASSWORD),
            data={'token': token.decode('ascii')})
        return response.json()


class IDTokenAuthentication(BaseOidcAuthentication):
    """Token based authentication using the JSON Web Token standard"""

    www_authenticate_realm = 'api'

    def authenticate(self, request):
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None
        payload = self.decode_jwt(jwt_value)
        self.validate_claims(payload)

        return AuthenticatedServiceClient.create(payload), True

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = setttings.BEARER_AUTH_HEADER_PREFIX.lower()

        if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)
        elif smart_text(auth[1]).count('.') != 2:
            return None

        return auth[1]

    def jwks(self):
        keys = KEYS()
        keys.load_from_url(self.oidc_config['jwks_uri'], verify=False)
        return keys

    @cached_property
    def issuer(self):
        return self.oidc_config['issuer']

    @cache(ttl=setttings.OIDC_JWKS_EXPIRATION_TIME)
    def decode_jwt(self, jwt_value):
        keys = self.jwks()
        try:
            id_token = JWS().verify_compact(jwt_value, keys=keys)
        except JWKESTException:
            msg = _('Invalid Authorization header. JWT Signature verification failed.')
            raise AuthenticationFailed(msg)
        except UnicodeDecodeError:
            msg = _('Bad token format. Token decoding failed.')
            raise AuthenticationFailed(msg)
        return id_token

    def get_audiences(self, id_token):
        return setttings.OIDC_AUDIENCES

    def validate_claims(self, id_token):
        if isinstance(id_token.get('aud'), six.string_types):
            # Support for multiple audiences
            id_token['aud'] = [id_token['aud']]

        if id_token.get('iss') != self.issuer:
            msg = _('Invalid Authorization header. Invalid JWT issuer.')
            raise AuthenticationFailed(msg)
        if not any(aud in self.get_audiences(id_token) for aud in id_token.get('aud', [])):
            msg = _('Invalid Authorization header. Invalid JWT audience.')
            raise AuthenticationFailed(msg)
        if settings.OIDC_AUTHORIZED_PARTY_CHECK:
            if len(id_token['aud']) > 1 and 'azp' not in id_token:
                msg = _('Invalid Authorization header. Missing JWT authorized party.')
                raise AuthenticationFailed(msg)
            if 'azp' in id_token and id_token['azp'] not in setttings.OIDC_AUDIENCES:
                msg = _('Invalid Authorization header. Invalid JWT authorized party.')
                raise AuthenticationFailed(msg)

        utc_timestamp = int(time.time())
        if utc_timestamp > id_token.get('exp', 0):
            msg = _('Invalid Authorization header. JWT has expired.')
            raise AuthenticationFailed(msg)
        if 'nbf' in id_token and utc_timestamp < id_token['nbf']:
            msg = _('Invalid Authorization header. JWT not yet valid.')
            raise AuthenticationFailed(msg)
        if 'iat' in id_token and utc_timestamp > id_token['iat'] + setttings.OIDC_LEEWAY:
            msg = _('Invalid Authorization header. JWT too old.')
            raise AuthenticationFailed(msg)
        if setttings.OIDC_SCOPE not in id_token.get('scope'):
            msg = _('Invalid Authorization header.  Invalid JWT scope.')
            raise AuthenticationFailed(msg)

    def authenticate_header(self, request):
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)
