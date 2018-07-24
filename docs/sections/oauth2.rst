.. _oauth2:

OAuth2 Server
#############

Because OIDC is a layer on top of the OAuth 2.0 protocol, this package also gives you a simple but effective OAuth2 server that you can use not only for logging in your users on multiple platforms, but also to protect other resources you want to expose.

Protecting Views
================

Here we are going to protect a view with a scope called ``read_books``::

    from django.http import JsonResponse
    from django.views.decorators.http import require_http_methods

    from oidc_provider.lib.utils.oauth2 import protected_resource_view


    @require_http_methods(['GET'])
    @protected_resource_view(['read_books'])
    def protected_api(request, *args, **kwargs):

        dic = {
            'protected': 'information',
        }

        return JsonResponse(dic, status=200)

Client Credentials Grant
========================

The client can request an access token using only its client credentials (ID and SECRET) when the client is requesting access to the protected resources under its control, that have been previously arranged with the authorization server using the ``client.scope`` field.

.. note::
    You can use Django admin to manually set the client scope or programmatically::

        client.scope = ['read_books', 'add_books']
        client.save()

This is how the request should look like::

    POST /token HTTP/1.1
    Host: localhost:8000
    Authorization: Basic eWZ3a3c0cWxtaHY0cToyVWE0QjVzRlhmZ3pNeXR5d1FqT01jNUsxYmpWeXhXeXRySVdsTmpQbld3\
    Content-Type: application/x-www-form-urlencoded

    grant_type=client_credentials

A successful access token response will like this::

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store
    Pragma: no-cache

    {
        "token_type"    : "Bearer",
        "access_token"  : "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzY3AiOlsib3BlbmlkIiw...",
        "expires_in"    : 3600,
        "scope"         : "read_books add_books"
    }

Token introspection can be used to validate access tokens requested with client credentials if the ``OIDC_INTROSPECTION_VALIDATE_AUDIENCE_SCOPE`` setting is ``False``.
