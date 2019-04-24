import json
import logging
import re

from django.http import HttpResponse
from django.http import JsonResponse

from oidc_provider import settings
from oidc_provider.lib.errors import RegisterError
from oidc_provider.lib.utils.register import create_client
from oidc_provider.models import Token

logger = logging.getLogger(__name__)


class RegisterEndpoint(object):

    def __init__(self, request):
        self.request = request
        self.params = {}
        self._extract_params()

    def _extract_params(self):
        jsonStr = self.request.body

        paramDic = json.loads(jsonStr.decode())

        self.params['name'] = paramDic.get('client_name', None)
        if 'redirect_uris' in paramDic:
            self.params['redirect_uris'] = '\n'.join(paramDic['redirect_uris'])
        else:
            self.params['redirect_uris'] = None
        if 'response_types' in paramDic:
            self.params['response_types'] = paramDic['response_types']
        else:
            self.params['response_types'] = ['code']

        self.params['access_token'] = None
        header_dic = self.request.META
        if 'HTTP_AUTHORIZATION' in header_dic:
            auth_header = header_dic['HTTP_AUTHORIZATION']
            if re.compile('^Bearer\\s.+$').match(auth_header):
                self.params['access_token'] = auth_header.split()[1]

    def validate_params(self):
        # Make sure appropriate parameters are there
        # See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
        # We want client name (optional), and redirect URIs (required).
        # "Response type" will default to code (Authorization code flow)

        # Is this endpoint enabled in the configuration?
        if not settings.get('OIDC_REGISTRATION_ENDPOINT_ENABLED'):
            raise RegisterError('invalid_request')

        # If authorization is required, has user provided valid access token?
        if settings.get('OIDC_REGISTRATION_ENDPOINT_REQ_TOKEN'):
            if self.params['access_token'] is None:
                raise RegisterError('invalid_request')
            # Check whether token is valid
            try:
                self.token = Token.objects.get(access_token=self.params['access_token'])

                if self.token.has_expired():
                    logger.error('[Register] Token has expired: %s', self.params['access_token'])
                    raise RegisterError('invalid_token')

                if not ('openid' in self.token.scope):
                    logger.error('[Register] Missing openid scope.')
                    raise RegisterError('insufficient_scope')

            except Token.DoesNotExist:
                # logger.error('[UserInfo] Token does not exist: %s', self.params.access_token)
                raise RegisterError('invalid_token')

        # Has the user provided redirect URIs in JSON?
        if self.params['redirect_uris'] is None:
            raise RegisterError('invalid_request')

    def create_response_dic(self):
        """
        Create a dictionary with client_id, client_secret, and
        client_secret_expires_at (set to 0 at this point)
        See: https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
        """
        client = create_client(redirect_uris=self.params['redirect_uris'],
                               name=self.params['name'],
                               response_types=self.params['response_types'])

        client.save()
        # At this point, no support for client secret expiration so
        # we return 0 meaning that it doesn't expire
        dic = {
            'client_id': client.client_id,
            'secret': client.client_secret,
            'redirect_uris': self.params['redirect_uris'],
            'client_secret_expires_at': '0'
        }

        return dic

    @classmethod
    def response(cls, dic):
        response = JsonResponse(dic, status=200)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'

        return response

    @classmethod
    def error_response(cls, code, description, status):
        response = HttpResponse(status=status)
        error_pattern = 'error="{0}", error_description="{1}"'
        response['WWW-Authenticate'] = error_pattern.format(code, description)

        return response
