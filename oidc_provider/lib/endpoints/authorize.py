import logging

from oidc_provider.lib.errors import *
from oidc_provider.lib.utils.params import *
from oidc_provider.lib.utils.token import *
from oidc_provider.models import *

logger = logging.getLogger(__name__)


class AuthorizeEndpoint(object):

    def __init__(self, request):

        self.request = request

        self.params = Params()

        # Because in this endpoint we handle both GET
        # and POST request.
        self.query_dict = (self.request.POST if self.request.method == 'POST'
                           else self.request.GET)

        self._extract_params()

        # Determine which flow to use.
        if self.params.response_type in ['code']:
            self.grant_type = 'authorization_code'
        elif self.params.response_type in ['id_token', 'id_token token']:
            self.grant_type = 'implicit'
            self._extract_implicit_params()
        else:
            self.grant_type = None

    def _extract_params(self):
        """
        Get all the params used by the Authorization Code Flow
        (and also for the Implicit).

        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        self.params.client_id = self.query_dict.get('client_id', '')
        self.params.redirect_uri = self.query_dict.get('redirect_uri', '')
        self.params.response_type = self.query_dict.get('response_type', '')
        self.params.scope = self.query_dict.get('scope', '').split()
        self.params.state = self.query_dict.get('state', '')

    def _extract_implicit_params(self):
        """
        Get specific params used by the Implicit Flow.

        See: http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
        """
        self.params.nonce = self.query_dict.get('nonce', '')

    def validate_params(self):

        if not self.params.redirect_uri:
            raise RedirectUriError()

        if not ('openid' in self.params.scope):
            raise AuthorizeError(
                self.params.redirect_uri,
                'invalid_scope',
                self.grant_type)

        try:
            self.client = Client.objects.get(client_id=self.params.client_id)

            if not (self.params.redirect_uri in self.client.redirect_uris):
                raise RedirectUriError()

            if not self.grant_type or not (self.params.response_type == self.client.response_type):

                raise AuthorizeError(
                    self.params.redirect_uri,
                    'unsupported_response_type',
                    self.grant_type)

        except Client.DoesNotExist:
            raise ClientIdError()

    def create_response_uri(self):
        try:
            if self.grant_type == 'authorization_code':
                code = create_code(
                    user=self.request.user,
                    client=self.client,
                    scope=self.params.scope)
                
                code.save()

                # Create the response uri.
                uri = self.params.redirect_uri + '?code={0}'.format(code.code)

            elif self.grant_type == 'implicit':
                id_token_dic = create_id_token(
                    user=self.request.user,
                    aud=self.client.client_id)

                token = create_token(
                    user=self.request.user,
                    client=self.client,
                    id_token_dic=id_token_dic,
                    scope=self.params.scope)

                # Store the token.
                token.save()

                id_token = encode_id_token(
                    id_token_dic, self.client.client_secret)

                # Create the response uri.
                uri = self.params.redirect_uri + \
                    '#token_type={0}&id_token={1}&expires_in={2}'.format(
                        'bearer',
                        id_token,
                        60 * 10,
                    )

                # Check if response_type is 'id_token token' then
                # add access_token to the fragment.
                if self.params.response_type == 'id_token token':
                    uri += '&access_token={0}'.format(token.access_token)
        except:
            logger.error('Authorization server error, grant_type: %s' %self.grant_type, extra={
                'redirect_uri': self.redirect_uri,
                'state': self.params.state
            })
            raise AuthorizeError(
                self.params.redirect_uri,
                'server_error',
                self.grant_type)

        # Add state if present.
        uri += ('&state={0}'.format(self.params.state) if self.params.state else '')

        return uri
