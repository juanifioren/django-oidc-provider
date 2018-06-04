.. _installation:

Installation
############

Requirements
============

* Python: ``2.7`` ``3.4`` ``3.5`` ``3.6``
* Django: ``1.8`` ``1.9`` ``1.10`` ``1.11`` ``2.0``

Quick Installation
==================

If you want to get started fast see our ``/example`` folder in your local installation. Or look at it `on github <https://github.com/juanifioren/django-oidc-provider/tree/master/example>`_.

Install the package using pip::

    $ pip install django-oidc-provider

Add it to your apps in your project's django settings::

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

Include our urls to your project's ``urls.py``::

    urlpatterns = patterns('',
        # ...
        url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),
        # ...
    )

Run the migrations and generate a server RSA key::

    $ python manage.py migrate
    $ python manage.py creatersakey

Add this required variable to your project's django settings::

    LOGIN_URL = '/accounts/login/'
