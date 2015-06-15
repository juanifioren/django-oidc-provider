from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.views.decorators.http import require_http_methods
from django.views.generic import View

from oidc_provider.lib.endpoints.authorize import *
from oidc_provider.lib.endpoints.discovery import *
from oidc_provider.lib.endpoints.token import *
from oidc_provider.lib.endpoints.userinfo import *
from oidc_provider.lib.errors import *


class AuthorizeView(View):

    def get(self, request, *args, **kwargs):

        authorize = AuthorizeEndpoint(request)

        try:
            authorize.validate_params()

            if request.user.is_authenticated():
                # Check if there's a hook setted.
                hook_resp = settings.get('OIDC_AFTER_USERLOGIN_HOOK')(
                    request=request, user=request.user,
                    client=authorize.client)
                if hook_resp:
                    return hook_resp

                # Generate hidden inputs for the form.
                context = {
                    'params': authorize.params,
                }
                hidden_inputs = render_to_string(
                    'oidc_provider/hidden_inputs.html', context)

                # Remove `openid` from scope list
                # since we don't need to print it.
                authorize.params.scope.remove('openid')

                context = {
                    'client': authorize.client,
                    'hidden_inputs': hidden_inputs,
                    'params': authorize.params,
                }

                return render(request, 'oidc_provider/authorize.html', context)
            else:
                path = request.get_full_path()
                return redirect_to_login(path)

        except (ClientIdError, RedirectUriError) as error:
            context = {
                'error': error.error,
                'description': error.description,
            }

            return render(request, 'oidc_provider/error.html', context)

        except (AuthorizeError) as error:
            uri = error.create_uri(
                authorize.params.redirect_uri,
                authorize.params.state)

            return HttpResponseRedirect(uri)

    def post(self, request, *args, **kwargs):

        authorize = AuthorizeEndpoint(request)

        allow = True if request.POST.get('allow') else False

        try:
            authorize.validate_params()
            
            if not allow:
                raise AuthorizeError(authorize.params.redirect_uri,
                                     'access_denied',
                                     authorize.grant_type)

            uri = authorize.create_response_uri()

            return HttpResponseRedirect(uri)

        except (AuthorizeError) as error:
            uri = error.create_uri(
                authorize.params.redirect_uri,
                authorize.params.state)

            return HttpResponseRedirect(uri)


class TokenView(View):

    def post(self, request, *args, **kwargs):
        
        token = TokenEndpoint(request)

        try:
            token.validate_params()

            dic = token.create_response_dic()

            return TokenEndpoint.response(dic)

        except (TokenError) as error:
            return TokenEndpoint.response(error.create_dict(), status=400)


@require_http_methods(['GET', 'POST'])
def userinfo(request):

    userinfo = UserInfoEndpoint(request)
    
    try:
        userinfo.validate_params()

        dic = userinfo.create_response_dic()

        return UserInfoEndpoint.response(dic)

    except (UserInfoError) as error:
        return UserInfoEndpoint.error_response(
            error.code,
            error.description,
            error.status)


class ProviderInfoView(View):

    def get(self, request, *args, **kwargs):

        dic = ProviderInfoEndpoint.create_response_dic()

        return JsonResponse(dic)