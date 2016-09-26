.. _accesstokens:

Access Tokens
#############

At the end of the login process, an access token is generated. This access token is the thing that's passed along with every API call (e.g. userinfo endpoint) as proof that the call was made by a specific person from a specific app.

Access tokens generally have a lifetime of only a couple of hours, you can use ``OIDC_TOKEN_EXPIRE`` to set custom expiration that suit your needs.

Obtaining an Access token
=========================

Go to the admin site and create a public client with a response_type ``id_token token`` and a redirect_uri ``http://example.org/``.

Open your browser and accept consent at::

    http://localhost:8000/authorize?client_id=651462&redirect_uri=http://example.org/&response_type=code&scope=openid email profile&state=123123

In the redirected URL you should have a ``code`` parameter included as query string::

    http://example.org/?code=b9cedb346ee04f15ab1d3ac13da92002&state=123123

We use ``code`` value to obtain ``access_token`` and ``refresh_token``::

    curl -X POST -H "Authorization: Basic NjUxNDYyOjM3YjFjNGZmODI2ZjhkNzhiZDQ1ZTI1YmFkNzVhMmMw" -H "Cache-Control: no-cache" -H "Content-Type: multipart/form-data" -F "code=b9cedb346ee04f15ab1d3ac13da92002" -F "redirect_uri=http://example.org/" -F "grant_type=authorization_code" "http://localhost:8000/token/"

Example response::

    {
        "access_token": "82b35f3d810f4cf49dd7a52d4b22a594",
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": "0bac2d80d75d46658b0b31d3778039bb",
        "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
    }

Then you can grab the access token and ask user data by doing a GET request to the ``/userinfo`` endpoint::

    http://localhost:8000/userinfo/?access_token=82b35f3d810f4cf49dd7a52d4b22a594

Expiration and Refresh of Access Tokens
=======================================

If you receive a ``401 Unauthorized`` status when issuing access token probably means that has expired.

The RP application obtains a new access token by sending a POST request to the ``/token`` endpoint with the following request parameters::

    curl -X POST -H "Cache-Control: no-cache" -H "Content-Type: multipart/form-data" -F "client_id=651462" -F "grant_type=refresh_token" -F "refresh_token=0bac2d80d75d46658b0b31d3778039bb" "http://localhost:8000/token/"
