from datetime import timedelta
import logging
try:
    from urllib import urlencode
    from urlparse import urlsplit, parse_qs, urlunsplit
except ImportError:
    from urllib.parse import urlsplit, parse_qs, urlunsplit, urlencode

from django.utils import timezone

from oidc_provider.lib.errors import *
from oidc_provider.lib.utils.params import *
from oidc_provider.lib.utils.token import *
from oidc_provider.models import *
from oidc_provider import settings


logger = logging.getLogger(__name__)


class AuthorizeEndpoint(object):

    def __init__(self, request):
        self.request = request
        self.params = Params()

        self._extract_params()

        # Determine which flow to use.
        if self.params.response_type in ['code']:
            self.grant_type = 'authorization_code'
        elif self.params.response_type in ['id_token', 'id_token token']:
            self.grant_type = 'implicit'
        else:
            self.grant_type = None

    def _extract_params(self):
        """
        Get all the params used by the Authorization Code Flow
        (and also for the Implicit).

        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        # Because in this endpoint we handle both GET
        # and POST request.
        query_dict = (self.request.POST if self.request.method == 'POST'
                      else self.request.GET)

        self.params.client_id = query_dict.get('client_id', '')
        self.params.redirect_uri = query_dict.get('redirect_uri', '')
        self.params.response_type = query_dict.get('response_type', '')
        self.params.scope = query_dict.get('scope', '').split()
        self.params.state = query_dict.get('state', '')
        self.params.nonce = query_dict.get('nonce', '')

    def validate_params(self):

        if not self.params.redirect_uri:
            logger.error('[Authorize] Missing redirect uri.')
            raise RedirectUriError()

        if not ('openid' in self.params.scope):
            logger.error('[Authorize] Missing openid scope.')
            raise AuthorizeError(
                self.params.redirect_uri,
                'invalid_scope',
                self.grant_type)

        try:
            self.client = Client.objects.get(client_id=self.params.client_id)

            clean_redirect_uri = urlsplit(self.params.redirect_uri)
            clean_redirect_uri = urlunsplit(clean_redirect_uri._replace(query=''))
            if not (clean_redirect_uri in self.client.redirect_uris):
                logger.error('[Authorize] Invalid redirect uri: %s', self.params.redirect_uri)
                raise RedirectUriError()

            if not self.grant_type or not (self.params.response_type == self.client.response_type):
                logger.error('[Authorize] Invalid response type: %s', self.params.response_type)
                raise AuthorizeError(
                    self.params.redirect_uri,
                    'unsupported_response_type',
                    self.grant_type)

        except Client.DoesNotExist:
            logger.error('[Authorize] Invalid client identifier: %s', self.params.client_id)
            raise ClientIdError()

    def create_response_uri(self):
        uri = urlsplit(self.params.redirect_uri)
        query_params = parse_qs(uri.query)
        query_fragment = parse_qs(uri.fragment)

        try:
            if self.grant_type == 'authorization_code':
                code = create_code(
                    user=self.request.user,
                    client=self.client,
                    scope=self.params.scope,
                    nonce=self.params.nonce)
                
                code.save()

                query_params['code'] = code.code
                query_params['state'] = self.params.state if self.params.state else ''

            elif self.grant_type == 'implicit':
                id_token_dic = create_id_token(
                    user=self.request.user,
                    aud=self.client.client_id,
                    nonce=self.params.nonce)

                token = create_token(
                    user=self.request.user,
                    client=self.client,
                    id_token_dic=id_token_dic,
                    scope=self.params.scope)

                # Store the token.
                token.save()

                query_fragment['token_type'] = 'bearer'
                query_fragment['id_token'] = encode_id_token(id_token_dic)
                query_fragment['expires_in'] = 60 * 10

                # Check if response_type is 'id_token token' then
                # add access_token to the fragment.
                if self.params.response_type == 'id_token token':
                    query_fragment['access_token'] = token.access_token

                query_fragment['state'] = self.params.state if self.params.state else ''

        except Exception as error:
            logger.error('[Authorize] Error when trying to create response uri: %s', error)
            raise AuthorizeError(
                self.params.redirect_uri,
                'server_error',
                self.grant_type)

        uri = uri._replace(query=urlencode(query_params, doseq=True))
        uri = uri._replace(fragment=urlencode(query_fragment, doseq=True))

        return urlunsplit(uri)

    def set_client_user_consent(self):
        """
        Save the user consent given to a specific client.

        Return None.
        """
        expires_at = timezone.now() + timedelta(
            days=settings.get('OIDC_SKIP_CONSENT_EXPIRE'))

        uc, created = UserConsent.objects.get_or_create(
            user=self.request.user,
            client=self.client,
            defaults={'expires_at': expires_at})
        uc.scope = self.params.scope

        # Rewrite expires_at if object already exists.
        if not created:
            uc.expires_at = expires_at

        uc.save()

    def client_has_user_consent(self):
        """
        Check if already exists user consent for some client.

        Return bool.
        """
        value = False
        try:
            uc = UserConsent.objects.get(user=self.request.user,
                                         client=self.client)
            if (set(self.params.scope).issubset(uc.scope)) and \
               not (uc.has_expired()):
                value = True
        except UserConsent.DoesNotExist:
            pass

        return value
