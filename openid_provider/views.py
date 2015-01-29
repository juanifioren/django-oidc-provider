import urllib

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect

from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.views.generic import View

from .lib.errors import *
from .lib.endpoints.authorize import *
from .lib.endpoints.token import *
from .lib.endpoints.userinfo import *

from openid_provider import settings


class AuthorizeView(View):

    def get(self, request, *args, **kwargs):

        authorize = AuthorizeEndpoint(request)

        try:
            authorize.validate_params()

            if request.user.is_authenticated():

                # This is for printing scopes in the form.
                authorize.params.scope_str = ' '.join(authorize.params.scope)

                context = {
                    'params': authorize.params,
                    'client': authorize.client,
                }

                return render(request, 'openid_provider/authorize.html', context)
            else:
                path = request.get_full_path()
                return redirect_to_login(
                    path, settings.get('LOGIN_URL'), REDIRECT_FIELD_NAME)

        except (ClientIdError, RedirectUriError) as error:
            context = {
                'error': error.error,
                'description': error.description,
            }

            return render(request, 'openid_provider/error.html', context)

        except (AuthorizeError) as error:
            uri = error.create_uri(
                authorize.params.redirect_uri,
                authorize.params.state)

            return HttpResponseRedirect(uri)

    def post(self, request, *args, **kwargs):

        authorize = AuthorizeEndpoint(request)

        allow = True if request.POST.get('allow') else False

        try: 
            uri = authorize.create_response_uri(allow)

            return HttpResponseRedirect(uri)

        except (AuthorizeError) as error:
            uri = error.create_uri(authorize.params.redirect_uri, authorize.params.state)

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
