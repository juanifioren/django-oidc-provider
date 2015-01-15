from django.conf import settings
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.views.generic import View
import urllib
from openid_provider.lib.errors import *
from openid_provider.lib.endpoints.authorize import *
from openid_provider.lib.endpoints.token import *
from openid_provider.lib.endpoints.userinfo import *


class AuthorizeView(View):

    def get(self, request, *args, **kwargs):

        authorize = AuthorizeEndpoint(request)

        try:
            authorize.validate_params()

            if request.user.is_authenticated():

                # This is for passing scopes into the form.
                authorize.params.scope_str = ' '.join(authorize.params.scope)

                data = {
                    'params': authorize.params,
                    'client': authorize.client,
                }

                return render(request, 'openid_provider/authorize.html', data)
            else:
                next = urllib.quote(request.get_full_path())
                login_url = settings.LOGIN_URL + '?next=' + next

                return HttpResponseRedirect(login_url)

        except (ClientIdError, RedirectUriError) as error:
            data = {
                'error': error.error,
                'description': error.description,
            }

            return render(request, 'openid_provider/error.html', data)

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