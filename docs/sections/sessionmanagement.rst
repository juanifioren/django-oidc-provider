.. _sessionmanagement:

Session Management
##################

The `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_ specification complements the core specification by defining how to monitor the End-User's login status at the OpenID Provider on an ongoing basis so that the Relying Party can log out an End-User who has logged out of the OpenID Provider.


Setup
=====

Somewhere in your Django ``settings.py``::

    MIDDLEWARE_CLASSES = [
        ...
        'oidc_provider.middleware.SessionManagementMiddleware',
    ]

    OIDC_SESSION_MANAGEMENT_ENABLE = True


If you're in a multi-server setup, you might also want to add ``OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY`` to your settings and set it to some random but fixed string. While authenticated clients have a session that can be used to calculate the browser state, there is no such thing for unauthenticated clients. Hence this value. By default a value is generated randomly on startup, so this will be different on each server. To get a consistent value across all servers you should set this yourself.


Example RP iframe
=================

::

    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="ISO-8859-1">
        <title>RP Iframe</title>
    </head>
    <body onload="javascript:startChecking()">
        <iframe id="op-iframe" src="http://localhost:8000/check-session-iframe/" frameborder="0" width="0" height="0"></iframe>
    </body>
    <script>
        var targetOP = "http://localhost:8000";

        window.addEventListener("message", receiveMessage, false);

        function startChecking() {
                  checkStatus();
                  setInterval('checkStatus()', 1000*60); // every 60 seconds
        }

        function checkStatus() {
                  var clientId = '';
                  var sessionState = '';
                  var data = clientId + ' ' + sessionState;
                  document.getElementById('op-iframe').contentWindow.postMessage(data, targetOP);
        }

        function receiveMessage(event) {
            if (event.origin !== targetOP) {
                // Origin did not come from the OP.
                return;
            }
            if (event.data === 'unchanged') {
                // User is still logged in to the OP.
            } else if (event.data === 'changed') {
                // Perform re-authentication with prompt=none to obtain the current session state at the OP.
            } else {
                // Error.
                console.log('Something goes wrong!');
            }
        }
    </script>
    </html>

RP-Initiated Logout
===================

An RP can notify the OP that the End-User has logged out of the site, and might want to log out of the OP as well. In this case, the RP, after having logged the End-User out of the RP, redirects the End-User's User Agent to the OP's logout endpoint URL.

This URL is normally obtained via the ``end_session_endpoint`` element of the OP's Discovery response.

Parameters that are passed as query parameters in the logout request:

* ``id_token_hint``
    Previously issued ID Token passed to the logout endpoint as a hint about the End-User's current authenticated session with the Client.
* ``post_logout_redirect_uri``
    URL to which the RP is requesting that the End-User's User Agent be redirected after a logout has been performed.
* ``state``
    OPTIONAL. Opaque value used by the RP to maintain state between the logout request and the callback to the endpoint specified by the ``post_logout_redirect_uri`` query parameter.

Example redirect::

    http://localhost:8000/end-session/?id_token_hint=eyJhbGciOiJSUzI1NiIsImtpZCI6ImQwM...&post_logout_redirect_uri=http://rp.example.com/logged-out/&state=c91c03ea6c46a86
