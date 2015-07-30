import logging
import re

from django.http import HttpResponse
from django.http import JsonResponse

from oidc_provider.lib.errors import *
from oidc_provider.lib.claims import *
from oidc_provider.lib.utils.params import *
from oidc_provider.models import *
from oidc_provider import settings


logger = logging.getLogger(__name__)


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
        Or try getting via GET.
        See: http://tools.ietf.org/html/rfc6750#section-2.1

        Return a string.
        """
        auth_header = self.request.META.get('HTTP_AUTHORIZATION', '')

        if re.compile('^Bearer\s{1}.+$').match(auth_header):
            access_token = auth_header.split()[1]
        else:
            access_token = self.request.GET.get('access_token', '')

        return access_token

    def validate_params(self):
        try:
            self.token = Token.objects.get(access_token=self.params.access_token)

            if self.token.has_expired():
                logger.error('[UserInfo] Token has expired: %s', self.params.access_token)
                raise UserInfoError('invalid_token')

            if not ('openid' in self.token.scope):
                logger.error('[UserInfo] Missing openid scope.')
                raise UserInfoError('insufficient_scope')

        except Token.DoesNotExist:
            logger.error('[UserInfo] Token does not exist: %s', self.params.access_token)
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

        standard_claims = StandardScopeClaims(self.token.user, self.token.scope)

        dic.update(standard_claims.create_response_dic())

        extra_claims = settings.get('OIDC_EXTRA_SCOPE_CLAIMS', import_str=True)(
            self.token.user, self.token.scope)

        dic.update(extra_claims.create_response_dic())

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
