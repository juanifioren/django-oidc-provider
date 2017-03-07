.. _accesstokens:

Access Tokens
#############

At the end of the login process, an access token is generated. This access token is the thing that's passed along with every API call (e.g. userinfo endpoint) as proof that the call was made by a specific person from a specific app.

Access tokens generally have a lifetime of only a couple of hours, you can use ``OIDC_TOKEN_EXPIRE`` to set custom expiration that suit your needs.

Obtaining an Access token
=========================

Go to the admin site and create a confidential client with ``response_type = code`` and ``redirect_uri = http://example.org/``.

Open your browser and accept consent at::

    http://localhost:8000/authorize?client_id=651462&redirect_uri=http://example.org/&response_type=code&scope=openid email profile&state=123123

In the redirected URL you should have a ``code`` parameter included as query string::

    http://example.org/?code=b9cedb346ee04f15ab1d3ac13da92002&state=123123

We use ``code`` value to obtain ``access_token`` and ``refresh_token``::

    curl -X POST \
        -H "Cache-Control: no-cache" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "http://localhost:8000/token/" \
        -d "client_id=651462" \
        -d "client_secret=37b1c4ff826f8d78bd45e25bad75a2c0" \
        -d "code=b9cedb346ee04f15ab1d3ac13da92002" \
        -d "redirect_uri=http://example.org/" \
        -d "grant_type=authorization_code"

Example response::

    {
        "access_token": "82b35f3d810f4cf49dd7a52d4b22a594",
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": "0bac2d80d75d46658b0b31d3778039bb",
        "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
    }

Then you can grab the access token and ask user data by doing a GET request to the ``/userinfo`` endpoint::

    curl -X GET \
        -H "Cache-Control: no-cache" \
        "http://localhost:8000/userinfo/?access_token=82b35f3d810f4cf49dd7a52d4b22a594"

Expiration and Refresh of Access Tokens
=======================================

If you receive a ``401 Unauthorized`` status when issuing access token probably means that has expired.

The RP application obtains a new access token by sending a POST request to the ``/token`` endpoint with the following request parameters::

    curl -X POST \
        -H "Cache-Control: no-cache" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "http://localhost:8000/token/" \
        -d "client_id=651462" \
        -d "client_secret=37b1c4ff826f8d78bd45e25bad75a2c0" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=0bac2d80d75d46658b0b31d3778039bb"
