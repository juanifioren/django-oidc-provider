import logging
import re

from django.http import HttpResponse
from django.http import JsonResponse

from oidc_provider.lib.errors import *
from oidc_provider.lib.claims import *
from oidc_provider.lib.utils.params import *

from oidc_provider.models import *
from oidc_provider import settings
from oidc_provider.lib.utils.register import *


logger = logging.getLogger(__name__)


class RegisterEndpoint(object):

    def __init__(self, request):
        jsonStr = request.body

        paramDic = json.loads(jsonStr)
            
        self.request = request
        self.params = Params()
        self.params.name = None
        self.params.access_token = None
        self.params.redirecturis = None
        self.params.response_types = 'code'
        # If client_name has been passed in
        if 'client_name' in paramDic: 
            self.params.name = paramDic['client_name']
        # If redirect_uris has been passed in
        if 'redirect_uris' in paramDic:
            self.params.redirecturis = '\n'.join(paramDic['redirect_uris'])
        if 'response_types' in paramDic :
            self.params.response_types = '\n'.join(paramDic['response_types'])
                 
        headerDic = request.META
        if 'HTTP_AUTHORIZATION' in headerDic:
            auth_header = headerDic['HTTP_AUTHORIZATION']
            if re.compile('^Bearer\s{1}.+$').match(auth_header):
                self.params.access_token = auth_header.split()[1]


 
    def _extract_params(self):
        # Get the parameters from request
        # self.params.name = self.request.POST.get('client_name', '')
        # self.params.redirecturis = self.request.POST.get('redirect_uris', '')
        pass
    
    def validate_params(self):
        # Make sure appropriate parameters are there
        # See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
        # We want client name (optional), and redirect URIs (required).  
        # "Response type" will default to code (Authorization code flow)
        
        # Is this endpoint enabled in the configuration?
        if not settings.get('REGISTRATION_ENDPOINT_ENABLED'):
            raise RegisterError('invalid_request')
            
        # If authorization is required, has user provided valid access token?
        if settings.get('REGISTRATION_ENDPOINT_REQ_TOKEN'):
            if self.params.access_token is None:
                raise RegisterError('invalid_request')
            # Check whether token is valid
            try: 
                self.token = Token.objects.get(access_token=self.params.access_token)
            
                if self.token.has_expired():
                    logger.error('[Register] Token has expired: %s', self.params.access_token)
                    raise RegisterError('invalid_token')

                if not ('openid' in self.token.scope):
                    logger.error('[Register] Missing openid scope.')
                    raise RegisterError('insufficient_scope')
            
            except Token.DoesNotExist:
                #logger.error('[UserInfo] Token does not exist: %s', self.params.access_token)
                raise RegisterError('invalid_token')
         
        # Has the user provided redirect URIs in JSON?
        if self.params.redirecturis is None:
            raise RegisterError('invalid_request') 
        
    def create_response_dic(self):
        """
        Create a dictionary with client_id, client_secret, and 
        client_secret_expires_at (set to 0 at this point)
        See: https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
        """
        client = create_client(redirect_uris=self.params.redirecturis, 
                               name=self.params.name, 
                               response_type=self.params.response_types)
        
        client.save()
        # At this point, no support for client secret expiration so
        # we return 0 meaning that it doesn't expire
        dic = {
            'id': client.client_id, 
            'secret': client.client_secret,
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
        response['WWW-Authenticate'] = 'error="{0}", error_description="{1}"'.format(code, description)

        return response

