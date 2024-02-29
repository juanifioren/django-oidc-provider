.. _installation:

Installation
############

Requirements
============

* Python: ``3.8`` ``3.9`` ``3.10`` ``3.11``
* Django: ``3.2`` ``4.2``

Quick Installation
==================

If you want to get started fast see our ``/example`` folder in your local installation. Or look at it `on github <https://github.com/juanifioren/django-oidc-provider/tree/master/example>`_.

Install the package using pip::

    $ pip install django-oidc-provider

Add it to your apps in your project's django settings::

    INSTALLED_APPS = [
        # ...
        'oidc_provider',
        # ...
    ]

Include our urls to your project's ``urls.py``::

    urlpatterns = [
        # ...
        path('openid/', include('oidc_provider.urls', namespace='oidc_provider')),
        # ...
    ]

Run the migrations and generate a server RSA key::

    $ python manage.py migrate
    $ python manage.py creatersakey

Add this required variable to your project's django settings::

    LOGIN_URL = '/accounts/login/'
