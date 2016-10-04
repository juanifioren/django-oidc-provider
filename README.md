# Django OIDC Provider

[![Python Versions](https://img.shields.io/pypi/pyversions/django-oidc-provider.svg)](https://pypi.python.org/pypi/django-oidc-provider)
[![PyPI Versions](https://img.shields.io/pypi/v/django-oidc-provider.svg)](https://pypi.python.org/pypi/django-oidc-provider)
[![Documentation Status](https://readthedocs.org/projects/django-oidc-provider/badge/?version=v0.4.x)](http://django-oidc-provider.readthedocs.io/en/v0.4.x/?badge=v0.4.x)
[![Travis](https://travis-ci.org/juanifioren/django-oidc-provider.svg?branch=v0.4.x)](https://travis-ci.org/juanifioren/django-oidc-provider)

## About OpenID

OpenID Connect is a simple identity layer on top of the OAuth 2.0 protocol, which allows computing clients to verify the identity of an end-user based on the authentication performed by an authorization server, as well as to obtain basic profile information about the end-user in an interoperable and REST-like manner. Like [Google](https://developers.google.com/identity/protocols/OpenIDConnect) for example.

## About the package

`django-oidc-provider` can help you providing out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects.

Support for Python 3 and 2. Also latest versions of django.

[Read docs for more info](http://django-oidc-provider.readthedocs.org/).

## Contributing

We love contributions, so please feel free to fix bugs, improve things, provide documentation. You SHOULD follow this steps:

* Fork the project.
* Make your feature addition or bug fix.
* Add tests for it inside `oidc_provider/tests`. Then run all and ensure everything is OK (read docs for how to test in all envs).
* Send pull request to the `develop` branch.
