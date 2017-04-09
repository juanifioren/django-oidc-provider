import logging
try:
    from urllib import urlencode
    from urlparse import urlsplit, parse_qs, urlunsplit
except ImportError:
    from urllib.parse import urlsplit, parse_qs, urlunsplit, urlencode

from Cryptodome.PublicKey import RSA
from django.contrib.auth.views import (
    redirect_to_login,
    logout,
)
from django.core.urlresolvers import reverse
from django.http import JsonResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.http import require_http_methods
from django.views.generic import View
from jwkest import long_to_base64

from oidc_provider.lib.claims import StandardScopeClaims
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from oidc_provider.lib.endpoints.token import TokenEndpoint
from oidc_provider.lib.errors import (
    AuthorizeError,
    ClientIdError,
    RedirectUriError,
    TokenError,
    UserAuthError)
from oidc_provider.lib.utils.common import (
    redirect,
    get_site_url,
    get_issuer,
)
from oidc_provider.lib.utils.oauth2 import protected_resource_view
from oidc_provider.lib.utils.token import client_id_from_id_token
from oidc_provider.models import (
    Client,
    RESPONSE_TYPE_CHOICES,
    RSAKey,
)
from oidc_provider import settings
from oidc_provider import signals


logger = logging.getLogger(__name__)


class AuthorizeView(View):

    def get(self, request, *args, **kwargs):

        authorize = AuthorizeEndpoint(request)

        try:
            authorize.validate_params()

            if request.user.is_authenticated():
                # Check if there's a hook setted.
                hook_resp = settings.get('OIDC_AFTER_USERLOGIN_HOOK', import_str=True)(
                    request=request, user=request.user,
                    client=authorize.client)
                if hook_resp:
                    return hook_resp

                if settings.get('OIDC_SKIP_CONSENT_ALWAYS') and not (authorize.client.client_type == 'public') \
                and not (authorize.params['prompt'] == 'consent'):
                    return redirect(authorize.create_response_uri())

                if settings.get('OIDC_SKIP_CONSENT_ENABLE'):
                    # Check if user previously give consent.
                    if authorize.client_has_user_consent() and not (authorize.client.client_type == 'public') \
                    and not (authorize.params['prompt'] == 'consent'):
                        return redirect(authorize.create_response_uri())

                if authorize.params['prompt'] == 'none':
                    raise AuthorizeError(authorize.params['redirect_uri'], 'interaction_required', authorize.grant_type)

                if authorize.params['prompt'] == 'login':
                    return redirect_to_login(request.get_full_path(), settings.get('OIDC_LOGIN_URL'))

                if authorize.params['prompt'] == 'select_account':
                    # TODO: see how we can support multiple accounts for the end-user.
                    raise AuthorizeError(authorize.params['redirect_uri'], 'account_selection_required', authorize.grant_type)

                # Generate hidden inputs for the form.
                context = {
                    'params': authorize.params,
                }
                hidden_inputs = render_to_string('oidc_provider/hidden_inputs.html', context)

                # Remove `openid` from scope list
                # since we don't need to print it.
                if 'openid' in authorize.params['scope']:
                    authorize.params['scope'].remove('openid')

                context = {
                    'client': authorize.client,
                    'hidden_inputs': hidden_inputs,
                    'params': authorize.params,
                    'scopes': authorize.get_scopes_information(),
                }

                return render(request, 'oidc_provider/authorize.html', context)
            else:
                if authorize.params['prompt'] == 'none':
                    raise AuthorizeError(authorize.params['redirect_uri'], 'login_required', authorize.grant_type)

                return redirect_to_login(request.get_full_path(), settings.get('OIDC_LOGIN_URL'))

        except (ClientIdError, RedirectUriError) as error:
            context = {
                'error': error.error,
                'description': error.description,
            }

            return render(request, 'oidc_provider/error.html', context)

        except (AuthorizeError) as error:
            uri = error.create_uri(
                authorize.params['redirect_uri'],
                authorize.params['state'])

            return redirect(uri)

    def post(self, request, *args, **kwargs):
        authorize = AuthorizeEndpoint(request)

        try:
            authorize.validate_params()

            if not request.POST.get('allow'):
                signals.user_decline_consent.send(self.__class__, user=request.user, client=authorize.client, scope=authorize.params['scope'])

                raise AuthorizeError(authorize.params['redirect_uri'],
                                     'access_denied',
                                     authorize.grant_type)

            signals.user_accept_consent.send(self.__class__, user=request.user, client=authorize.client, scope=authorize.params['scope'])

            # Save the user consent given to the client.
            authorize.set_client_user_consent()

            uri = authorize.create_response_uri()

            return redirect(uri)

        except (AuthorizeError) as error:
            uri = error.create_uri(
                authorize.params['redirect_uri'],
                authorize.params['state'])

            return redirect(uri)


class TokenView(View):

    def post(self, request, *args, **kwargs):
        token = TokenEndpoint(request)

        try:
            token.validate_params()

            dic = token.create_response_dic()

            return TokenEndpoint.response(dic)

        except TokenError as error:
            return TokenEndpoint.response(error.create_dict(), status=400)
        except UserAuthError as error:
            return TokenEndpoint.response(error.create_dict(), status=403)


@require_http_methods(['GET', 'POST'])
@protected_resource_view(['openid'])
def userinfo(request, *args, **kwargs):
    """
    Create a diccionary with all the requested claims about the End-User.
    See: http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

    Return a diccionary.
    """
    token = kwargs['token']

    dic = {
        'sub': token.id_token.get('sub'),
    }

    standard_claims = StandardScopeClaims(token)
    dic.update(standard_claims.create_response_dic())

    if settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
        extra_claims = settings.get('OIDC_EXTRA_SCOPE_CLAIMS', import_str=True)(token)
        dic.update(extra_claims.create_response_dic())

    response = JsonResponse(dic, status=200)
    response['Access-Control-Allow-Origin'] = '*'
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'

    return response


class ProviderInfoView(View):

    def get(self, request, *args, **kwargs):
        dic = dict()

        site_url = get_site_url(request=request)
        dic['issuer'] = get_issuer(site_url=site_url, request=request)

        dic['authorization_endpoint'] = site_url + reverse('oidc_provider:authorize')
        dic['token_endpoint'] = site_url + reverse('oidc_provider:token')
        dic['userinfo_endpoint'] = site_url + reverse('oidc_provider:userinfo')
        dic['end_session_endpoint'] = site_url + reverse('oidc_provider:end-session')

        types_supported = [x[0] for x in RESPONSE_TYPE_CHOICES]
        dic['response_types_supported'] = types_supported

        dic['jwks_uri'] = site_url + reverse('oidc_provider:jwks')

        dic['id_token_signing_alg_values_supported'] = ['HS256', 'RS256']

        # See: http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
        dic['subject_types_supported'] = ['public']

        dic['token_endpoint_auth_methods_supported'] = ['client_secret_post',
                                                        'client_secret_basic']

        if settings.get('OIDC_SESSION_MANAGEMENT_ENABLE'):
            dic['check_session_iframe'] = site_url + reverse('oidc_provider:check-session-iframe')

        response = JsonResponse(dic)
        response['Access-Control-Allow-Origin'] = '*'

        return response


class JwksView(View):

    def get(self, request, *args, **kwargs):
        dic = dict(keys=[])

        for rsakey in RSAKey.objects.all():
            public_key = RSA.importKey(rsakey.key).publickey()
            dic['keys'].append({
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'kid': rsakey.kid,
                'n': long_to_base64(public_key.n),
                'e': long_to_base64(public_key.e),
            })

        response = JsonResponse(dic)
        response['Access-Control-Allow-Origin'] = '*'

        return response


class EndSessionView(View):

    def get(self, request, *args, **kwargs):
        id_token_hint = request.GET.get('id_token_hint', '')
        post_logout_redirect_uri = request.GET.get('post_logout_redirect_uri', '')
        state = request.GET.get('state', '')
        client = None

        next_page = settings.get('OIDC_LOGIN_URL')
        after_end_session_hook = settings.get('OIDC_AFTER_END_SESSION_HOOK', import_str=True)

        if id_token_hint:
            client_id = client_id_from_id_token(id_token_hint)
            try:
                client = Client.objects.get(client_id=client_id)
                if post_logout_redirect_uri in client.post_logout_redirect_uris:
                    if state:
                        uri = urlsplit(post_logout_redirect_uri)
                        query_params = parse_qs(uri.query)
                        query_params['state'] = state
                        uri = uri._replace(query=urlencode(query_params, doseq=True))
                        next_page = urlunsplit(uri)
                    else:
                        next_page = post_logout_redirect_uri
            except Client.DoesNotExist:
                pass

        after_end_session_hook(
            request=request,
            id_token=id_token_hint,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=state,
            client=client,
            next_page=next_page
        )

        return logout(request, next_page=next_page)


class CheckSessionIframeView(View):

    @method_decorator(xframe_options_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(CheckSessionIframeView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return render(request, 'oidc_provider/check_session_iframe.html', kwargs)
