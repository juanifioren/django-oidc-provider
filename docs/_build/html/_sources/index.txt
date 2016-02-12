Welcome to Django OIDC Provider Documentation!
==============================================

Django OIDC Provider can help you providing out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects.

Before getting started there are some important things that you should know:

* Although OpenID was built on top of OAuth2, this isn't an OAuth2 server. Maybe in a future it will be.
* Despite that implementation MUST support TLS. You can make request without using SSL. There is no control on that.
* This cover **Authorization Code Flow**  and **Implicit Flow**, NO support for **Hybrid Flow** at this moment.
* Only support for requesting Claims using Scope Values.

Contents:

.. toctree::
   :maxdepth: 2
   
   installation
   clients
   serverkeys
   templates
   claims
   settings
   contribute
   
..

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

