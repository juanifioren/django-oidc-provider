from base64 import b64decode, urlsafe_b64encode
import hashlib
import logging
import re

from oidc_provider.lib.utils.common import cleanup_url_from_query_string

try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

from django.http import JsonResponse

from oidc_provider.lib.errors import (
    TokenError,
)
from oidc_provider.lib.utils.token import (
    create_id_token,
    create_token,
    encode_id_token,
)
from oidc_provider.models import (
    Client,
    Code,
    Token,
)
from oidc_provider import settings


logger = logging.getLogger(__name__)


class TokenEndpoint(object):

    def __init__(self, request):
        self.request = request
        self.params = {}
        self._extract_params()

    def _extract_params(self):
        client_id, client_secret = self._extract_client_auth()

        self.params['client_id'] = client_id
        self.params['client_secret'] = client_secret
        self.params['redirect_uri'] = unquote(
            self.request.POST.get('redirect_uri', '').split('?', 1)[0])
        self.params['grant_type'] = self.request.POST.get('grant_type', '')
        self.params['code'] = self.request.POST.get('code', '')
        self.params['state'] = self.request.POST.get('state', '')
        self.params['scope'] = self.request.POST.get('scope', '')
        self.params['refresh_token'] = self.request.POST.get('refresh_token', '')
        # PKCE parameter.
        self.params['code_verifier'] = self.request.POST.get('code_verifier')

    def _extract_client_auth(self):
        """
        Get client credentials using HTTP Basic Authentication method.
        Or try getting parameters via POST.
        See: http://tools.ietf.org/html/rfc6750#section-2.1

        Return a string.
        """
        auth_header = self.request.META.get('HTTP_AUTHORIZATION', '')

        if re.compile('^Basic\s{1}.+$').match(auth_header):
            b64_user_pass = auth_header.split()[1]
            try:
                user_pass = b64decode(b64_user_pass).decode('utf-8').split(':')
                client_id, client_secret = tuple(user_pass)
            except:
                client_id = client_secret = ''
        else:
            client_id = self.request.POST.get('client_id', '')
            client_secret = self.request.POST.get('client_secret', '')

        return (client_id, client_secret)

    def validate_params(self):
        try:
            self.client = Client.objects.get(client_id=self.params['client_id'])
        except Client.DoesNotExist:
            logger.debug('[Token] Client does not exist: %s', self.params['client_id'])
            raise TokenError('invalid_client')

        if self.client.client_type == 'confidential':
            if not (self.client.client_secret == self.params['client_secret']):
                logger.debug('[Token] Invalid client secret: client %s do not have secret %s',
                             self.client.client_id, self.client.client_secret)
                raise TokenError('invalid_client')

        if self.params['grant_type'] == 'authorization_code':
            clean_redirect_uri = cleanup_url_from_query_string(self.params['redirect_uri'])
            if not (clean_redirect_uri in self.client.redirect_uris):
                logger.debug('[Token] Invalid redirect uri: %s', self.params['redirect_uri'])
                raise TokenError('invalid_client')

            try:
                self.code = Code.objects.get(code=self.params['code'])
            except Code.DoesNotExist:
                logger.debug('[Token] Code does not exist: %s', self.params['code'])
                raise TokenError('invalid_grant')

            if not (self.code.client == self.client) \
               or self.code.has_expired():
                logger.debug('[Token] Invalid code: invalid client or code has expired',
                             self.params['redirect_uri'])
                raise TokenError('invalid_grant')

            # Validate PKCE parameters.
            if self.params['code_verifier']:
                if self.code.code_challenge_method == 'S256':
                    new_code_challenge = urlsafe_b64encode(
                            hashlib.sha256(self.params['code_verifier'].encode('ascii')).digest()
                        ).decode('utf-8').replace('=', '')
                else:
                    new_code_challenge = self.params['code_verifier']

                # TODO: We should explain the error.
                if not (new_code_challenge == self.code.code_challenge):
                    raise TokenError('invalid_grant')

        elif self.params['grant_type'] == 'refresh_token':
            if not self.params['refresh_token']:
                logger.debug('[Token] Missing refresh token')
                raise TokenError('invalid_grant')

            try:
                self.token = Token.objects.get(refresh_token=self.params['refresh_token'],
                                               client=self.client)

            except Token.DoesNotExist:
                logger.debug('[Token] Refresh token does not exist: %s', self.params['refresh_token'])
                raise TokenError('invalid_grant')

        else:
            logger.debug('[Token] Invalid grant type: %s', self.params['grant_type'])
            raise TokenError('unsupported_grant_type')

    def create_response_dic(self):
        if self.params['grant_type'] == 'authorization_code':
            return self.create_code_response_dic()
        elif self.params['grant_type'] == 'refresh_token':
            return self.create_refresh_response_dic()

    def create_code_response_dic(self):
        token = create_token(
            user=self.code.user,
            client=self.code.client,
            scope=self.code.scope)

        if self.code.is_authentication:
            id_token_dic = create_id_token(
                user=self.code.user,
                aud=self.client.client_id,
                nonce=self.code.nonce,
                at_hash=token.at_hash,
                request=self.request,
                scope=self.params['scope'],
            )
        else:
            id_token_dic = {}
        token.id_token = id_token_dic

        # Store the token.
        token.save()

        # We don't need to store the code anymore.
        self.code.delete()

        dic = {
            'access_token': token.access_token,
            'refresh_token': token.refresh_token,
            'token_type': 'bearer',
            'expires_in': settings.get('OIDC_TOKEN_EXPIRE'),
            'id_token': encode_id_token(id_token_dic, token.client),
        }

        return dic

    def create_refresh_response_dic(self):
        token = create_token(
            user=self.token.user,
            client=self.token.client,
            scope=self.token.scope)

        # If the Token has an id_token it's an Authentication request.
        if self.token.id_token:
            id_token_dic = create_id_token(
                user=self.token.user,
                aud=self.client.client_id,
                nonce=None,
                at_hash=token.at_hash,
                request=self.request,
                scope=self.params['scope'],
            )
        else:
            id_token_dic = {}
        token.id_token = id_token_dic

        # Store the token.
        token.save()

        # Forget the old token.
        self.token.delete()

        dic = {
            'access_token': token.access_token,
            'refresh_token': token.refresh_token,
            'token_type': 'bearer',
            'expires_in': settings.get('OIDC_TOKEN_EXPIRE'),
            'id_token': encode_id_token(id_token_dic, self.token.client),
        }

        return dic

    @classmethod
    def response(cls, dic, status=200):
        """
        Create and return a response object.
        """
        response = JsonResponse(dic, status=status)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'

        return response
