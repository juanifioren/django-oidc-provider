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


RP-Initiated Logout
===================

An RP can notify the OP that the End-User has logged out of the site, and might want to log out of the OP as well. In this case, the RP, after having logged the End-User out of the RP, redirects the End-User's User Agent to the OP's logout endpoint URL.

This URL is normally obtained via the ``end_session_endpoint`` element of the OP's Discovery response.

Parameters that are passed as query parameters in the logout request:

* ``id_token_hint``
    RECOMMENDED. Previously issued ID Token passed to the logout endpoint as a hint about the End-User's current authenticated session with the Client.
* ``post_logout_redirect_uri``
    OPTIONAL. URL to which the RP is requesting that the End-User's User Agent be redirected after a logout has been performed.
    
    The value must be a valid, encoded URL that has been registered in the list of "Post Logout Redirect URIs" in your Client (RP) page.
* ``state``
    OPTIONAL. Opaque value used by the RP to maintain state between the logout request and the callback to the endpoint specified by the ``post_logout_redirect_uri`` query parameter.

Example redirect::

    http://localhost:8000/end-session/?id_token_hint=eyJhbGciOiJSUzI1NiIsImtpZCI6ImQwM...&post_logout_redirect_uri=http%3A%2F%2Frp.example.com%2Flogged-out%2F&state=c91c03ea6c46a86

**Logout consent prompt**

The standard defines that the logout flow should be interrupted to prompt the user for consent if the OpenID provider cannot verify that the request was made by the user.

We enforce this behavior by displaying a logout consent prompt if it detects any of the following conditions:

* If ``id_token_hint`` is not present or is invalid (we could not validate the client from it).
* If ``post_logout_redirect_uri`` is not registered in the list of "Post Logout Redirect URIs".

If the user confirms the logout request, we continue the logout flow. To modify the logout consent template create your own ``oidc_provider/end_session_prompt.html``.

**Other scenarios**

In some cases, there may be no valid redirect URI for the user after logging out (e.g., the OP could not find a post-logout URI). If the user ends up being logged out, the system will render the ``oidc_provider/end_session_completed.html`` template.

On the other hand, if the session remains active for any reason, the ``oidc_provider/end_session_failed.html`` template will be used.

Both templates will receive the ``{{ client }}`` variable in their context.

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


