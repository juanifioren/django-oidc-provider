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
