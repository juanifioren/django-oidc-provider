.. _examples:

Examples
########

Pure JS client using Implicit Flow
==================================

Testing OpenID Connect flow can be as simple as putting one file with a few functions on the client and calling the provider. Let me show.

**01. Setup the provider**

You can use the example project code to run your OIDC Provider at ``localhost:8000``.

Go to the admin site and create a public client with a response_type ``id_token token`` and a redirect_uri ``http://localhost:3000``.

.. note::
    Remember to create at least one **RSA Key** for the server with ``python manage.py creatersakey``

**02. Create the client**

As relying party we are going to use a JS library created by Nat Sakimura. `Here is the article <https://nat.sakimura.org/2014/12/10/making-a-javascript-openid-connect-client/>`_.

**index.html**::

    <!DOCTYPE html>
    <html>
    <head>

        <title>OIDC RP</title>

    </head>
    <body>

        <center>
            <h1>OpenID Connect RP Example</h1>
            <button id="login-button">Login</button>
        </center>

        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.2/jquery.min.js"></script>
        <script src="https://www.sakimura.org/test/openidconnect.js"></script>

        <script type="text/javascript">
        $(function() {
            var clientInfo = {
                client_id : '',
                redirect_uri : 'http://localhost:3000'
            };

            OIDC.setClientInfo(clientInfo);

            var providerInfo = OIDC.discover('http://localhost:8000');

            OIDC.setProviderInfo(providerInfo);
            OIDC.storeInfo(providerInfo, clientInfo);

            // Restore configuration information.
            OIDC.restoreInfo();

            // Get Access Token
            var token = OIDC.getAccessToken();

            // Make userinfo request using access_token.
            if (token !== null) {
                $.get('http://localhost:8000/userinfo/?access_token='+token, function( data ) {
                    alert('USERINFO: '+ JSON.stringify(data));
                });
            }

            // Make an authorization request if the user click the login button.
            $('#login-button').click(function (event) {
                OIDC.login({
                    scope : 'openid profile email',
                    response_type : 'id_token token'
                });
            });
        });
        </script>

    </body>
    </html>

.. note::
    Remember that you must set your client_id (line 21).

**03. Make an authorization request**

By clicking the login button an authorization request has been made to the provider. After you accept it, the provider will redirect back to your previously registered ``redirect_uri`` with all the tokens requested.

**04. Requesting user information**

Now having the access_token in your hands you can request the user information by making a request to the ``/userinfo`` endpoint of the provider.

In this example we display information in the alert box.
