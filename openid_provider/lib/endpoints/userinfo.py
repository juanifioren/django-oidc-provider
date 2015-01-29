import re
from django.http import HttpResponse

try:  # JsonResponse is only available in Django > 1.7
    from django.http import JsonResponse
except ImportError:
    from ..utils.http import JsonResponse

from ..errors import *
from ..scopes import *
from ..utils.params import *
from openid_provider.models import *


class UserInfoEndpoint(object):

    def __init__(self, request):

        self.request = request
        self.params = Params()
        self._extract_params()

    def _extract_params(self):

        # TODO: Maybe add other ways of passing access token
        # http://tools.ietf.org/html/rfc6750#section-2
        self.params.access_token = self._get_access_token()

    def _get_access_token(self):
        """
        Get the access token using Authorization Request Header Field method.
        See: http://tools.ietf.org/html/rfc6750#section-2.1

        Return a string.
        """
        auth_header = self.request.META.get('HTTP_AUTHORIZATION', '')

        if re.compile('^Bearer\s{1}.+$').match(auth_header):
            access_token = auth_header.split()[1]
        else:
            access_token = ''

        return access_token

    def validate_params(self):
        
        try:
            self.token = Token.objects.get(access_token=self.params.access_token)

        except Token.DoesNotExist:
            raise UserInfoError('invalid_token')

    def create_response_dic(self):
        """
        Create a diccionary with all the requested claims about the End-User.
        See: http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

        Return a diccionary.
        """
        dic = {
            'sub': self.token.id_token.get('sub'),
        }

        standard_claims = StandardClaims(self.token.user, self.token.scope)
        
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