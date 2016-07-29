.. _installation:

Installation
############

Requirements
============

* Python: ``2.7`` ``3.4`` ``3.5``
* Django: ``1.7`` ``1.8`` ``1.9``

Quick Installation
==================

If you want to get started fast see our ``/example_project`` folder.

Install the package using pip::

    $ pip install django-oidc-provider

Add it to your apps::

    INSTALLED_APPS = (
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'oidc_provider',
        # ...
    )

Add the provider urls::

    urlpatterns = patterns('',
        # ...
        url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),
        # ...
    )

Generate server RSA key and run migrations (if you don't)::

    $ python manage.py creatersakey
    $ python manage.py migrate

Add required variables to your project settings::

    LOGIN_URL = '/accounts/login/'
