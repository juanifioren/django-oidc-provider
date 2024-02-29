import typing
from datetime import timedelta
import logging

import requests

try:
    from urllib import urlencode
    from urlparse import urlsplit, parse_qs, urlunsplit
except ImportError:
    from urllib.parse import urlsplit, parse_qs, urlunsplit, urlencode

from django.utils import timezone

from oidc_provider.lib.claims import StandardScopeClaims
from oidc_provider.lib.errors import (
    AuthorizeError,
    ClientIdError,
    RedirectUriError,
)
from oidc_provider.lib.utils.token import (
    create_code,
    create_id_token,
    create_token,
    encode_id_token, client_id_from_id_token, create_logout_token,
    encode_logout_token,
)
from oidc_provider.models import (
    Client,
    UserConsent,
)
from oidc_provider import settings
from oidc_provider.lib.utils.common import get_session_state

logger = logging.getLogger(__name__)


class AuthorizeEndpoint(object):
    _allowed_prompt_params = {'none', 'login', 'consent', 'select_account'}
    client_class = Client

    def __init__(self, request):
        self.request = request
        self.params = {}

        self._extract_params()

        # Determine which flow to use.
        if self.params['response_type'] in ['code']:
            self.grant_type = 'authorization_code'
        elif self.params['response_type'] in ['id_token', 'id_token token', 'token']:
            self.grant_type = 'implicit'
        elif self.params['response_type'] in [
             'code token', 'code id_token', 'code id_token token']:
            self.grant_type = 'hybrid'
        else:
            self.grant_type = None

        # Determine if it's an OpenID Authentication request (or OAuth2).
        self.is_authentication = 'openid' in self.params['scope']

    def _extract_params(self):
        """
        Get all the params used by the Authorization Code Flow
        (and also for the Implicit and Hybrid).

        See: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        """
        # Because in this endpoint we handle both GET
        # and POST request.
        query_dict = (self.request.POST if self.request.method == 'POST'
                      else self.request.GET)

        self.params['client_id'] = query_dict.get('client_id', '')
        self.params['redirect_uri'] = query_dict.get('redirect_uri', '')
        self.params['response_type'] = query_dict.get('response_type', '')
        self.params['scope'] = query_dict.get('scope', '').split()
        self.params['state'] = query_dict.get('state', '')
        self.params['nonce'] = query_dict.get('nonce', '')

        self.params['prompt'] = self._allowed_prompt_params.intersection(
            set(query_dict.get('prompt', '').split()))

        self.params['code_challenge'] = query_dict.get('code_challenge', '')
        self.params['code_challenge_method'] = query_dict.get('code_challenge_method', '')

    def validate_params(self):
        # Client validation.
        try:
            self.client = self.client_class.objects.get(client_id=self.params['client_id'])
        except Client.DoesNotExist:
            logger.debug('[Authorize] Invalid client identifier: %s', self.params['client_id'])
            raise ClientIdError()

        # Redirect URI validation.
        if self.is_authentication and not self.params['redirect_uri']:
            logger.debug('[Authorize] Missing redirect uri.')
            raise RedirectUriError()
        if not (self.params['redirect_uri'] in self.client.redirect_uris):
            logger.debug('[Authorize] Invalid redirect uri: %s', self.params['redirect_uri'])
            raise RedirectUriError()

        # Grant type validation.
        if not self.grant_type:
            logger.debug('[Authorize] Invalid response type: %s', self.params['response_type'])
            raise AuthorizeError(
                self.params['redirect_uri'], 'unsupported_response_type', self.grant_type)

        if (not self.is_authentication and (self.grant_type == 'hybrid' or
           self.params['response_type'] in ['id_token', 'id_token token'])):
            logger.debug('[Authorize] Missing openid scope.')
            raise AuthorizeError(self.params['redirect_uri'], 'invalid_scope', self.grant_type)

        # Nonce parameter validation.
        if self.is_authentication and self.grant_type == 'implicit' and not self.params['nonce']:
            raise AuthorizeError(self.params['redirect_uri'], 'invalid_request', self.grant_type)

        # Response type parameter validation.
        if self.is_authentication \
                and self.params['response_type'] not in self.client.response_type_values():
            raise AuthorizeError(self.params['redirect_uri'], 'invalid_request', self.grant_type)

        # PKCE validation of the transformation method.
        if self.params['code_challenge']:
            if not (self.params['code_challenge_method'] in ['plain', 'S256']):
                raise AuthorizeError(
                    self.params['redirect_uri'], 'invalid_request', self.grant_type)

    def create_code(self):
        code = create_code(
            user=self.request.user,
            client=self.client,
            scope=self.params['scope'],
            nonce=self.params['nonce'],
            is_authentication=self.is_authentication,
            code_challenge=self.params['code_challenge'],
            code_challenge_method=self.params['code_challenge_method'],
        )

        return code

    def create_token(self):
        token = create_token(
            user=self.request.user,
            client=self.client,
            scope=self.params['scope'],
        )

        return token

    def create_response_uri(self):
        uri = urlsplit(self.params['redirect_uri'])
        query_params = parse_qs(uri.query)
        query_fragment = {}

        try:
            if self.grant_type in ['authorization_code', 'hybrid']:
                code = self.create_code()
                code.save()
            if self.grant_type == 'authorization_code':
                query_params['code'] = code.code
                query_params['state'] = self.params['state'] if self.params['state'] else ''
            elif self.grant_type in ['implicit', 'hybrid']:
                token = self.create_token()

                # Check if response_type must include access_token in the response.
                if (self.params['response_type'] in
                   ['id_token token', 'token', 'code token', 'code id_token token']):
                    query_fragment['access_token'] = token.access_token

                # We don't need id_token if it's an OAuth2 request.
                if self.is_authentication:
                    kwargs = {
                        'token': token,
                        'user': self.request.user,
                        'aud': self.client.client_id,
                        'nonce': self.params['nonce'],
                        'request': self.request,
                        'scope': self.params['scope'],
                    }
                    # Include at_hash when access_token is being returned.
                    if 'access_token' in query_fragment:
                        kwargs['at_hash'] = token.at_hash
                    id_token_dic = create_id_token(**kwargs)

                    # Check if response_type must include id_token in the response.
                    if self.params['response_type'] in [
                            'id_token', 'id_token token', 'code id_token', 'code id_token token']:
                        query_fragment['id_token'] = encode_id_token(id_token_dic, self.client)
                else:
                    id_token_dic = {}

                # Store the token.
                token.id_token = id_token_dic
                token.save()

                # Code parameter must be present if it's Hybrid Flow.
                if self.grant_type == 'hybrid':
                    query_fragment['code'] = code.code

                query_fragment['token_type'] = 'bearer'

                query_fragment['expires_in'] = settings.get('OIDC_TOKEN_EXPIRE')

                query_fragment['state'] = self.params['state'] if self.params['state'] else ''

            if settings.get('OIDC_SESSION_MANAGEMENT_ENABLE'):
                session_state = get_session_state(
                    request=self.request,
                    client=self.client,
                    reference_uri=self.params['redirect_uri'],
                )
                if self.grant_type == 'authorization_code':
                    query_params['session_state'] = session_state
                elif self.grant_type in ['implicit', 'hybrid']:
                    query_fragment['session_state'] = session_state

        except Exception as error:
            logger.exception('[Authorize] Error when trying to create response uri: %s', error)
            raise AuthorizeError(self.params['redirect_uri'], 'server_error', self.grant_type)

        uri = uri._replace(
            query=urlencode(query_params, doseq=True),
            fragment=uri.fragment + urlencode(query_fragment, doseq=True))

        return urlunsplit(uri)

    def create_login_url(self):
        """Generate login url for provider."""
        return settings.get('OIDC_LOGIN_URL')

    def set_client_user_consent(self):
        """
        Save the user consent given to a specific client.

        Return None.
        """
        date_given = timezone.now()
        expires_at = date_given + timedelta(
            days=settings.get('OIDC_SKIP_CONSENT_EXPIRE'))

        uc, created = UserConsent.objects.get_or_create(
            user=self.request.user,
            client=self.client,
            defaults={
                'expires_at': expires_at,
                'date_given': date_given,
            }
        )
        uc.scope = self.params['scope']

        # Rewrite expires_at and date_given if object already exists.
        if not created:
            uc.expires_at = expires_at
            uc.date_given = date_given

        uc.save()

    def client_has_user_consent(self):
        """
        Check if already exists user consent for some client.

        Return bool.
        """
        value = False
        try:
            uc = UserConsent.objects.get(user=self.request.user, client=self.client)
            if (set(self.params['scope']).issubset(uc.scope)) and not (uc.has_expired()):
                value = True
        except UserConsent.DoesNotExist:
            pass

        return value

    def is_client_allowed_to_skip_consent(self):
        implicit_flow_resp_types = {'id_token', 'id_token token'}
        return (
            self.client.client_type != 'public' or
            self.params['response_type'] in implicit_flow_resp_types
        )

    def get_scopes_information(self):
        """
        Return a list with the description of all the scopes requested.
        """
        scopes = StandardScopeClaims.get_scopes_info(self.params['scope'])
        if settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
            scopes_extra = settings.get(
                'OIDC_EXTRA_SCOPE_CLAIMS', import_str=True).get_scopes_info(self.params['scope'])
            for index_extra, scope_extra in enumerate(scopes_extra):
                for index, scope in enumerate(scopes[:]):
                    if scope_extra['scope'] == scope['scope']:
                        del scopes[index]
        else:
            scopes_extra = []

        return scopes + scopes_extra


class EndSessionEndpoint:
    """Logout user for OP and RPs."""

    def __init__(self, request):
        self.request = request
        self.params = {}

        self._extract_params()
        self._client = self._get_client()
        self._next_page = self._get_next_page()

    @property
    def next_page(self):
        return self._next_page

    def call_after_end_session_hook(self):
        """Call after endsession hook."""
        after_end_session_hook = settings.get(
            'OIDC_AFTER_END_SESSION_HOOK',
            import_str=True,
        )
        after_end_session_hook(
            request=self.request,
            id_token=self._id_token_hint,
            post_logout_redirect_uri=self._post_logout_redirect_uri,
            state=self._state,
            client=self._client,
            next_page=self._next_page
        )

    def end_session_in_rps(self):
        """
        End session for all the connected RPs.

        https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest
        """
        if not settings.get('OIDC_BACKCHANNEL_LOGOUT_ENABLE'):
            return

        queryset = Client.objects.get_queryset()
        if self._client:
            queryset = queryset.exclude(client_id=self._client.client_id)

        for client in queryset.all():
            if client.backchannel_logout_uri:
                self._end_session_in_rp(client)

    def _end_session_in_rp(self, client: Client):
        sid = get_session_state(
            self.request,
            client, client.backchannel_logout_uri,
        )
        logout_token_dic = create_logout_token(
            user=self.request.user,
            aud=client.client_id,
            sid=sid,
            request=self.request,
        )
        logout_token = encode_logout_token(logout_token_dic, client)
        response = requests.post(
            client.backchannel_logout_uri,
            data={
                'logout_token': logout_token,
            },
        )
        if response.status_code != 200:
            logger.error(f'Failed to logout RP {client.client_id}')

    def _extract_params(self):
        """
        Get all the params used by End Session request.

        See: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
        """
        # Because in this endpoint we handle both GET and POST request.
        query_dict = (self.request.POST if self.request.method == 'POST'
                      else self.request.GET)

        self._id_token_hint = query_dict.get('id_token_hint', '')
        self._post_logout_redirect_uri = query_dict.get(
            'post_logout_redirect_uri', '',
        )
        self._state = query_dict.get('state', '')

    def _get_client(self) -> typing.Optional[Client]:
        client = None
        if self._id_token_hint:
            client_id = client_id_from_id_token(self._id_token_hint)
            try:
                client = Client.objects.get(client_id=client_id)
            except Client.DoesNotExist:
                pass

        return client

    def _get_next_page(self) -> typing.Optional[str]:
        next_page = settings.get('OIDC_LOGIN_URL')
        if not self._client:
            return next_page

        if self._post_logout_redirect_uri in self._client.post_logout_redirect_uris:  # noqa
            if self._state:
                uri = urlsplit(self._post_logout_redirect_uri)
                query_params = parse_qs(uri.query)
                query_params['state'] = self._state
                uri = uri._replace(
                    query=urlencode(query_params, doseq=True),
                )
                next_page = urlunsplit(uri)
            else:
                next_page = self._post_logout_redirect_uri

        return next_page
