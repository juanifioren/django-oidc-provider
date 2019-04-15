.. _tokenintrospection:

Token Introspection
###################

The `OAuth 2.0 Authorization Framework <https://tools.ietf.org/html/rfc6749>`_ extends its scope with many other speficications. One of these is the `OAuth 2.0 Token Introspection (RFC 7662) <https://tools.ietf.org/html/rfc7662>`_ which defines a protocol that allows authorized protected resources to query the authorization server to determine the set of metadata for a given token that was presented to them by an OAuth 2.0 client.

Client Setup
============
In order to enable this feature, some configurations must be performed in the ``Client``.

- The scope key:``token_introspection`` must be added to the client's scope.

If ``OIDC_INTROSPECTION_VALIDATE_AUDIENCE_SCOPE`` is set to ``True`` then:

- The ``client_id`` must be added to the client's scope.

Introspection Endpoint
======================
The introspection endpoint ``(/introspect)`` is an OAuth 2.0 endpoint that takes a parameter representing an OAuth 2.0 token and returns a JSON document representing the meta information surrounding the token.

The introspection endpoint its called using an HTTP POST request with parameters sent as *"application/x-www-form-urlencoded"* and **Basic authentication** (``base64(client_id:client_secret``).

Parameters:

* ``token``
    REQUIRED. The string value of an ``access_token`` previously issued.

Example request::

        curl -X POST \
        http://localhost:8000/introspect \
        -H 'Authorization: Basic NDgwNTQ2OmIxOGIyODVmY2E5N2Fm' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d token=6dd4b859706944848183d26f2fcb99c6

Example Response::

        {
            "aud": "480546",
            "sub": "1",
            "exp": 1538971676,
            "iat": 1538971076,
            "iss": "http://localhost:8000",
            "active": true,
            "client_id": "480546"
        }

Introspection Endpoint Errors
=============================
In case of error, the Introspection Endpoint will return a JSON document with the key ``active: false``

Example Error Response::

        {
            "active": "false"
        }
