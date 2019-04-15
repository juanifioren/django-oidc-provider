Welcome to Django OIDC Provider Documentation!
==============================================

This tiny (but powerful!) package can help you to provide out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects. And as a side effect a fair implementation of OAuth2.0 too. Covers Authorization Code, Implicit and Hybrid flows.

Also implements the following specifications:

* `OpenID Connect Discovery 1.0 <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
* `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
* `OAuth 2.0 for Native Apps <https://tools.ietf.org/html/draft-ietf-oauth-native-apps-01>`_
* `OAuth 2.0 Resource Owner Password Credentials Grant <https://tools.ietf.org/html/rfc6749#section-4.3>`_
* `Proof Key for Code Exchange by OAuth Public Clients <https://tools.ietf.org/html/rfc7636>`_

--------------------------------------------------------------------------------

Before getting started there are some important things that you should know:

* Despite that implementation MUST support TLS, you *can* make request without using SSL. There is no control on that.
* Supports only requesting Claims using Scope values, so you cannot request individual Claims.
* If you enable the Resource Owner Password Credentials Grant, you MUST implement protection against brute force attacks on the token endpoint

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
   sections/tokenintrospection
   sections/settings
   sections/signals
   sections/examples
   sections/contribute
   sections/changelog
..

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
