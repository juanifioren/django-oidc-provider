import logging

from django.http import JsonResponse

from oidc_provider.lib.errors import TokenIntrospectionError
from oidc_provider.lib.utils.common import get_basic_client_credentials, run_processing_hook
from oidc_provider.models import Token, get_resource_model


Resource = get_resource_model()

logger = logging.getLogger(__name__)


class TokenIntrospectionEndpoint(object):

    def __init__(self, request):
        self.request = request
        self.params = {}
        self._extract_params()

    def _extract_params(self):
        # Introspection only supports POST requests
        self.params['token'] = self.request.POST.get('token')
        resource_id, resource_secret = get_basic_client_credentials(self.request)
        self.params['resource_id'] = resource_id
        self.params['resource_secret'] = resource_secret

    def validate_params(self):
        if not (self.params['resource_id'] and self.params['resource_secret']):
            logger.debug('[Introspection] No resource credentials provided')
            raise TokenIntrospectionError()
        if not self.params['token']:
            logger.debug('[Introspection] No token provided')
            raise TokenIntrospectionError()
        try:
            token = Token.objects.get(access_token=self.params['token'])
        except Token.DoesNotExist:
            logger.debug('[Introspection] Token does not exist: %s', self.params['token'])
            raise TokenIntrospectionError()
        if token.has_expired():
            logger.debug('[Introspection] Token is not valid: %s', self.params['token'])
            raise TokenIntrospectionError()
        if not token.id_token:
            logger.debug('[Introspection] Token not an authentication token: %s', self.params['token'])
            raise TokenIntrospectionError()

        self.id_token = token.id_token
        audience = self.id_token.get('aud')
        if not audience:
            logger.debug('[Introspection] No audience found for token: %s', self.params['token'])
            raise TokenIntrospectionError()

        try:
            self.resource = Resource.objects.get(
                resource_id=self.params['resource_id'],
                resource_secret=self.params['resource_secret'],
                active=True,
                allowed_clients__client_id__contains=audience)
        except Resource.DoesNotExist:
            logger.debug('[Introspection] No valid resource id and audience: %s, %s',
                         self.params['resource_id'], audience)
            raise TokenIntrospectionError()

    def create_response_dic(self):
        response_dic = dict((k, self.id_token[k]) for k in ('sub', 'exp', 'iat', 'iss'))
        response_dic['active'] = True
        response_dic['client_id'] = self.id_token.get('aud')
        response_dic['aud'] = self.resource.resource_id

        response_dic = run_processing_hook(response_dic, 'OIDC_INTROSPECTION_PROCESSING_HOOK',
                                           resource=self.resource,
                                           id_token=self.id_token)

        return response_dic

    @classmethod
    def response(cls, dic, status=200):
        """
        Create and return a response object.
        """
        response = JsonResponse(dic, status=status)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'

        return response
