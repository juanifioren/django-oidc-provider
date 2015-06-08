import logging
import urllib

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

        logger.debug('Request %s', self.request)
        logger.debug('TokenEndPoint request.POST --> : %s', self.request.POST)
        logger.debug('TokenEndpoint request.GET --> : %s', self.request.GET)
        logger.debug('TokenEndPoint extract_params --> : %s', self.params.__dict__)

    def _extract_params(self):
        query_dict = self.request.POST

        self.params.client_id = query_dict.get('client_id', '')
        self.params.client_secret = query_dict.get('client_secret', '')
        self.params.redirect_uri = urllib.unquote(
            query_dict.get('redirect_uri', ''))
        self.params.grant_type = query_dict.get('grant_type', '')
        self.params.code = query_dict.get('code', '')
        self.params.state = query_dict.get('state', '')

    def validate_params(self):
        if not (self.params.grant_type == 'authorization_code'):
            logger.error('Unsupported grant type: --> : %s', self.params.grant_type)
            raise TokenError('unsupported_grant_type')

        try:
            self.client = Client.objects.get(client_id=self.params.client_id)

            if not (self.client.client_secret == self.params.client_secret):
                logger.error('Invalid client, client secret -->: %s', self.params.client_secret)
                raise TokenError('invalid_client')

            if not (self.params.redirect_uri in self.client.redirect_uris):
                logger.error('Invalid client, redirect_uri --> : %s', self.params.redirect_uri)
                raise TokenError('invalid_client')

            self.code = Code.objects.get(code=self.params.code)

            if not (self.code.client == self.client) \
               or self.code.has_expired():
                logger.error('Invalid grant, code client --> %s', self.code.client)
                raise TokenError('invalid_grant')

        except Client.DoesNotExist:
            raise TokenError('invalid_client')

        except Code.DoesNotExist:
            raise TokenError('invalid_grant')

    def create_response_dic(self):
        id_token_dic = create_id_token(
            user=self.code.user,
            aud=self.client.client_id)

        token = create_token(
            user=self.code.user,
            client=self.code.client,
            id_token_dic=id_token_dic,
            scope=self.code.scope)

        # Store the token.
        token.save()

        # We don't need to store the code anymore.
        self.code.delete()

        id_token = encode_id_token(id_token_dic, self.client.client_secret)

        dic = {
            'access_token': token.access_token,
            'token_type': 'bearer',
            'expires_in': settings.get('OIDC_TOKEN_EXPIRE'),
            'id_token': id_token,
        }
        logger.debug('Response dictionary --> : %s', dic)
        return dic

    @classmethod
    def response(cls, dic, status=200):
        """
        Create and return a response object.
        """
        response = JsonResponse(dic, status=status)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'

        logger.debug('JSON Response --> : %s', response.__dict__)

        return response
