from datetime import timedelta
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.utils import timezone
import urllib
import uuid
import json
import jwt
import random
import re
import time
from openid_provider.models import *
from openid_provider.lib.errors import *
from openid_provider.lib.scopes import *


class AuthorizeEndpoint(object):

    def __init__(self, request):

        self.request = request
        self.extract_params()

    def extract_params(self):

        query_dict = self.request.POST if self.request.method == 'POST' else self.request.GET

        class Params(object): pass

        Params.client_id = query_dict.get('client_id', '')
        Params.redirect_uri = query_dict.get('redirect_uri', '')
        Params.response_type = query_dict.get('response_type', '')
        Params.scope = query_dict.get('scope', '')
        Params.state = query_dict.get('state', '')

        self.params = Params

    def validate_params(self):

        if not self.params.redirect_uri:
            raise RedirectUriError()

        if not ('openid' in self.params.scope.split()):
            raise AuthorizeError(self.params.redirect_uri, 'invalid_scope')

        try:
            self.client = Client.objects.get(client_id=self.params.client_id)

            if not (self.params.redirect_uri in self.client.redirect_uris):
                raise RedirectUriError()

            if not (self.params.response_type == 'code'):
                raise AuthorizeError(self.params.redirect_uri, 'unsupported_response_type')

        except Client.DoesNotExist:
            raise ClientIdError()

    def create_response_uri(self, allow):

        if not allow:
            raise AuthorizeError(self.params.redirect_uri, 'access_denied')

        try:
            self.validate_params()
            
            code = Code()
            code.user = self.request.user
            code.client = self.client
            code.code = uuid.uuid4().hex
            code.expires_at = timezone.now() + timedelta(seconds=60*10)
            code.scope = self.params.scope

            code.save()
        except:
            raise AuthorizeError(self.params.redirect_uri, 'server_error')

        uri = self.params.redirect_uri + '?code={0}'.format(code.code)

        # Add state if present.
        uri = uri + ('&state={0}'.format(self.params.state) if self.params.state else '')

        return uri

class TokenEndpoint(object):

    def __init__(self, request):

        self.request = request
        self.extract_params()

    def extract_params(self):

        query_dict = self.request.POST

        class Params(object): pass

        Params.client_id = query_dict.get('client_id', '')
        Params.client_secret = query_dict.get('client_secret', '')
        Params.redirect_uri = urllib.unquote(query_dict.get('redirect_uri', ''))
        Params.grant_type = query_dict.get('grant_type', '')
        Params.code = query_dict.get('code', '')
        Params.state = query_dict.get('state', '')

        self.params = Params

    def validate_params(self):
        
        if not (self.params.grant_type == 'authorization_code'):
            raise TokenError('unsupported_grant_type')

        try:
            self.client = Client.objects.get(client_id=self.params.client_id)

            if not (self.client.client_secret == self.params.client_secret):
                raise TokenError('invalid_client')

            if not (self.params.redirect_uri in self.client.redirect_uris):
                raise TokenError('invalid_client')

            self.code = Code.objects.get(code=self.params.code)

            if not (self.code.client == self.client) and not self.code.has_expired():
                raise TokenError('invalid_grant')

        except Client.DoesNotExist:
            raise TokenError('invalid_client')

        except Code.DoesNotExist:
            raise TokenError('invalid_grant')

    def create_response_dic(self):

        expires_in = 60*60 # TODO: Probably add into settings

        token = Token()
        token.user = self.code.user
        token.client = self.code.client
        token.access_token = uuid.uuid4().hex

        id_token_dic = self.generate_id_token_dic()
        token.id_token = id_token_dic

        token.refresh_token = uuid.uuid4().hex
        token.expires_at = timezone.now() + timedelta(seconds=expires_in)
        token.scope = self.code.scope

        token.save()

        self.code.delete()

        id_token = jwt.encode(id_token_dic, self.client.client_secret)

        dic = {
            'access_token': token.access_token,
            'token_type': 'bearer',
            'expires_in': expires_in,
            'id_token': id_token,
            # TODO: 'refresh_token': token.refresh_token,
        }

        return dic

    def generate_id_token_dic(self):

        expires_in = 60*10

        now = timezone.now()

        # Convert datetimes into timestamps.
        iat_time = time.mktime(now.timetuple())
        exp_time = time.mktime((now + timedelta(seconds=expires_in)).timetuple())
        user_auth_time = time.mktime(self.code.user.last_login.timetuple())

        dic = {
            'iss': 'https://localhost:8000', # TODO: this should not be hardcoded.
            'sub': self.code.user.id,
            'aud': self.client.client_id,
            'exp': exp_time,
            'iat': iat_time,
            'auth_time': user_auth_time,
        }

        return dic

    @classmethod
    def response(self, dic, status=200):
        '''
        Create and return a response object.
        '''
        response = JsonResponse(dic, status=status)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'

        return response

class UserInfoEndpoint(object):

    def __init__(self, request):

        self.request = request
        self.extract_params()

    def extract_params(self):

        # TODO: Add other ways of passing access token
        # http://tools.ietf.org/html/rfc6750#section-2

        class Params(object): pass

        Params.access_token = self._get_access_token()

        self.params = Params

    def validate_params(self):
        
        try:
            self.token = Token.objects.get(access_token=self.params.access_token)

        except Token.DoesNotExist:
            raise UserInfoError('invalid_token')

    def _get_access_token(self):
        '''
        Get the access token using Authorization Request Header Field method.
        See: http://tools.ietf.org/html/rfc6750#section-2.1

        Return a string.
        '''
        auth_header = self.request.META.get('HTTP_AUTHORIZATION', '')

        if re.compile('^Bearer\s{1}.+$').match(auth_header):
            access_token = auth_header.split()[1]
        else:
            access_token = ''

        return access_token

    def create_response_dic(self):
        '''
        Create a diccionary with all the requested claims about the End-User.
        See: http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

        Return a diccionary.
        '''
        dic = {
            'sub': self.token.id_token.get('sub'),
        }

        standard_claims = StandardClaims(self.token.user, self.token.scope.split())
        
        dic.update(standard_claims.create_response_dic())

        return dic

    @classmethod
    def response(self, dic):

        response = JsonResponse(dic, status=200)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'

        return response

    @classmethod
    def error_response(self, code, description, status):

        response = HttpResponse(status=status)
        response['WWW-Authenticate'] = 'error="{0}", error_description="{1}"'.format(code, description)

        return response