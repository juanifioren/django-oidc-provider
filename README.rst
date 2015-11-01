
Django OIDC Provider
####################
.. image:: https://img.shields.io/pypi/pyversions/django-oidc-provider.svg
    :target: https://pypi.python.org/pypi/django-oidc-provider

.. image:: https://img.shields.io/pypi/v/django-oidc-provider.svg
    :target: https://pypi.python.org/pypi/django-oidc-provider

.. image:: https://travis-ci.org/juanifioren/django-oidc-provider.svg?branch=master
    :target: http://travis-ci.org/juanifioren/django-oidc-provider

.. image:: https://img.shields.io/pypi/dm/django-oidc-provider.svg
    :target: https://pypi.python.org/pypi/django-oidc-provider

************
About OpenID
************

OpenID Connect is a simple identity layer on top of the OAuth 2.0 protocol, which allows computing clients to verify the identity of an end-user based on the authentication performed by an authorization server, as well as to obtain basic profile information about the end-user in an interoperable and REST-like manner. `Google <https://developers.google.com/identity/protocols/OpenIDConnect>`_ is a good example of an OpenID Provider.

*****************
About the package
*****************

Django OIDC Provider can help you providing out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects.

Support for Python 3 and 2. Also latest versions of django.

Read docs for more info.

https://github.com/juanifioren/django-oidc-provider/blob/v0.2.1/DOC.md

See changelog here.

https://github.com/juanifioren/django-oidc-provider/blob/master/CHANGELOG.md

****************
Examples running
****************

* **BAID** by Government of Buenos Aires City. (`view site <https://id.buenosaires.gob.ar/>`_)
* **Example OIDC provider** by Juan Ignacio Fiorentino. (`view site <http://openid.juanifioren.com/>`_)

************
Contributing
************

We love contributions, so please feel free to fix bugs, improve things, provide documentation. You SHOULD follow this steps:

* Fork the project.
* Make your feature addition or bug fix.
* Add tests for it inside :code:`oidc_provider/tests`. Then run all and ensure everything is OK (read docs for how to test in all envs). 
* Send pull request to the specific version branch.
