Welcome to Django OIDC Provider Documentation!
==============================================

This tiny (but powerful!) package can help you providing out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects. And as a side effect a fair implementation of OAuth2.0 too. Covers Authorization Code, Implicit and Hybrid flows.

Also implements the following specifications:

* `OpenID Connect Discovery 1.0 <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
* `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
* `OAuth 2.0 for Native Apps <https://tools.ietf.org/html/draft-ietf-oauth-native-apps-01>`_
* `Proof Key for Code Exchange by OAuth Public Clients <https://tools.ietf.org/html/rfc7636>`_

--------------------------------------------------------------------------------

Before getting started there are some important things that you should know:

* Despite that implementation MUST support TLS. You can make request without using SSL. There is no control on that.
* Supports only for requesting Claims using Scope values.

--------------------------------------------------------------------------------

Contents:

.. toctree::
   :maxdepth: 2

   sections/installation
   sections/relyingparties
   sections/serverkeys
   sections/templates
   sections/scopesclaims
   sections/userconsent
   sections/oauth2
   sections/accesstokens
   sections/sessionmanagement
   sections/settings
   sections/signals
   sections/examples
   sections/contribute
..

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
