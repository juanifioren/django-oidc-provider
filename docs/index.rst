Welcome to Django OIDC Provider Documentation!
==============================================

Django OIDC Provider can help you providing out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects. And as a side effect a fair implementation of OAuth2.0 too.

--------------------------------------------------------------------------------

Before getting started there are some important things that you should know:

* Despite that implementation MUST support TLS. You can make request without using SSL. There is no control on that.
* This cover **Authorization Code Flow**  and **Implicit Flow**, NO support for **Hybrid Flow** at this moment.
* Only support for requesting Claims using Scope Values.

--------------------------------------------------------------------------------

Contents:

.. toctree::
   :maxdepth: 2
   
   sections/installation
   sections/clients
   sections/serverkeys
   sections/templates
   sections/claims
   sections/oauth2
   sections/settings
   sections/contribute
..

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

