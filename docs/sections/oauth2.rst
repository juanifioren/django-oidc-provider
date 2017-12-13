.. _oauth2:

OAuth2 Server
#############

Because OIDC is a layer on top of the OAuth 2.0 protocol, this package also gives you a simple but effective OAuth2 server that you can use not only for logging in your users on multiple platforms, but also to protect other resources you want to expose.

Protecting Views
================

Here we are going to protect a view with a scope called ``testscope``::

    from django.http import JsonResponse
    from django.views.decorators.http import require_http_methods

    from oidc_provider.lib.utils.oauth2 import protected_resource_view


    @require_http_methods(['GET'])
    @protected_resource_view(['testscope'])
    def protected_api(request, *args, **kwargs):

        dic = {
            'protected': 'information',
        }

        return JsonResponse(dic, status=200)
