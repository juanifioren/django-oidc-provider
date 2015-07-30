from base64 import b64decode
import logging
import re
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

from django.http import JsonResponse

from oidc_provider.lib.errors import *
from oidc_provider.lib.utils.params import *
from oidc_provider.lib.utils.token import *
from oidc_provider.models import *
from oidc_provider import settings


logger = logging.getLogger(__name__)


class TokenEndpoint(object):

    def __init__(self, request):
        self.request = request
        self.params = Params()
        self._extract_params()

    def _extract_params(self):
        client_id, client_secret = self._extract_client_auth()

        self.params.client_id = client_id
        self.params.client_secret = client_secret
        self.params.redirect_uri = unquote(
            self.request.POST.get('redirect_uri', ''))
        self.params.grant_type = self.request.POST.get('grant_type', '')
        self.params.code = self.request.POST.get('code', '')
        self.params.state = self.request.POST.get('state', '')

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
        if not (self.params.grant_type == 'authorization_code'):
            logger.error('[Token] Invalid grant type: %s', self.params.grant_type)
            raise TokenError('unsupported_grant_type')

        try:
            self.client = Client.objects.get(client_id=self.params.client_id)

            if not (self.client.client_secret == self.params.client_secret):
                logger.error('[Token] Invalid client secret: client %s do not have secret %s',
                             self.client.client_id, self.client.client_secret)
                raise TokenError('invalid_client')

            if not (self.params.redirect_uri in self.client.redirect_uris):
                logger.error('[Token] Invalid redirect uri: %s', self.params.redirect_uri)
                raise TokenError('invalid_client')

            self.code = Code.objects.get(code=self.params.code)

            if not (self.code.client == self.client) \
               or self.code.has_expired():
                logger.error('[Token] Invalid code: invalid client or code has expired',
                             self.params.redirect_uri)
                raise TokenError('invalid_grant')

        except Client.DoesNotExist:
            logger.error('[Token] Client does not exist: %s', self.params.client_id)
            raise TokenError('invalid_client')

        except Code.DoesNotExist:
            logger.error('[Token] Code does not exist: %s', self.params.code)
            raise TokenError('invalid_grant')

    def create_response_dic(self):
        id_token_dic = create_id_token(
            user=self.code.user,
            aud=self.client.client_id,
            nonce=self.code.nonce,
        )

        token = create_token(
            user=self.code.user,
            client=self.code.client,
            id_token_dic=id_token_dic,
            scope=self.code.scope)

        # Store the token.
        token.save()

        # We don't need to store the code anymore.
        self.code.delete()

        dic = {
            'access_token': token.access_token,
            'token_type': 'bearer',
            'expires_in': settings.get('OIDC_TOKEN_EXPIRE'),
            'id_token': encode_id_token(id_token_dic),
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
