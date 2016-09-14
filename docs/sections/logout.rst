.. logout:

Logout
######

OpenId Connect provides several mechanisms to handle logout requests via a Relying Party (RP) or directly with the OpenId Provider (OP).

The following sections explain the specifications implemented by this OP.

Front-Channel Logout
====================

When using the Front-Channel Logout specification there are two possible ways for a user to logout: *OP initiated* and *RP initiated*.

The *OP initiated* logout begins when an authenticated user requests to be logged out using the OP's site. It ends the user's session and requests each RP to logout the same user by using an ``iframe`` (without any user interaction).

The *RP initiated* logout begins when an authenticated user requests to be logged out using the RP's site. It ends the user's session and redirects them to the ``end_session_endpoint`` of the OP to end the session there too.

Because of how these options work, this OP defines one endpoint and a template tag for *RP* and *OP initiated* logout, respectively.

OP initiated logout
-------------------

As mentioned before, this method begins when an authenticated user requests to be logged out at the OP's site. Usually, this means a request to the `logout <https://docs.djangoproject.com/en/dev/topics/auth/default/#django.contrib.auth.logout>`_ view. At this point the OP's site has two options: redirect the user or render a logged out page.

Because ``django-oidc-provider`` doesn't have control over which option is chosen, it's responsibility of the OP's site (i.e. anyone using this app) to include the tag ``logout_clients`` in the first page that is shown to the user after requesting logout.

To enable this logout method RPs must implement the Section 2 of the `specification <http://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout>`_ and provide a value for the property ``frontchannel_logout_uri`` when creating a Client record.

Additionally RPs can define if ``frontchannel_logout_session_supported`` is supported. If that's the case, this OP will send a request to the endpoint with a ``iss`` and ``sid`` parameter. It's the RP's responsibility to act upon those parameters correctly.

.. note::
    The ``iss`` (issuer) and ``sid`` (session identifier) parameters are available to the RP only when ``frontchannel_logout_session_supported`` is ``true``. ``sid`` is available as a claim in the ``id_token`` delivered by this OP when appropriated.


``logout_clients`` template tag
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
This tag must be included at the page that is immediately shown to the user after logging out of this OP.

To include the tag, add the following to your template::

    {% load frontchannel_logout %}
    ...
    {% logout_clients %}

Once include, the tag will render the proper set of ``iframes`` pointing to each RP as configured.

.. tip::
    If needed, the template used to render the set of ``iframes`` can be overridden at ``oidc_provider/logout_clients.html``. The urls for logging out each RP is available as ``logout_urls``.

RP initiated logout
-------------------

In this case the user requests to be logged out at the RP's site. When this happens the RP ends the user's session and redirects them to the OP's ``end_session_endpoint`` where the session finished too. Then the OP issues a redirect to the original RP if needed.

The ``end_session_endpoint`` can be invoked without any parameters, in which case it will redirect the user to the ``LOGIN_URL`` endpoint after being logged out. In other cases, it can take up to three parameters:
 * ``id_token_hint``: The token issued by the OP. If sent by the RP, it will be validated and checked that it actually belongs to the user being logged out.
 * ``post_logout_redirect_uri``: URI that this OP will redirect the user after being logged out. It must have been previously registered for the Client.
 * ``state``: Value that will be sent again as parameter to the ``post_logout_redirect_uri`` if provided.

In case something goes wrong with the parameters, this OP will report the error with ``400`` status code (Bad Request), along with a plain text message indicating the cause.


