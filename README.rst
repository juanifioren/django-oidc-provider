
.. image:: http://s1.postimg.org/qcm2dtr6n/title.png
####################################################

**This project is in ALFA version and is rapidly changing. DO NOT USE IT FOR PRODUCTION SITES.**

Important things that you should know:

- Although OpenID was built on top of OAuth2, this isn't an OAuth2 server. Maybe in a future it will be.
- This cover ``authorization_code`` flow and ``implicit`` flow, NO support for ``hybrid`` flow at this moment.
- Only support for requesting Claims using Scope Values.

************
Installation
************

Install the package using pip.

.. code:: bash

    pip install https://github.com/juanifioren/django-openid-provider/archive/master.zip


Add it to your apps.

.. code:: python

    INSTALLED_APPS = (
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'openid_provider',
        # ...
    )

Add the provider urls.

.. code:: python

    urlpatterns = patterns('',
        # ...
        url(r'^openid/', include('openid_provider.urls', namespace='openid_provider')),
        # ...
    )

********
Settings
********

Add required variables to your project settings.

.. code:: python

    # REQUIRED. Your server provider url.
    SITE_URL = 'http://localhost:8000'

    # REQUIRED. 
    # See: https://docs.djangoproject.com/en/1.7/ref/settings/#login-url
    LOGIN_URL = '/accounts/login/'

********************
Create User & Client
********************

First of all, we need to create a user: ``python manage.py createsuperuser``.

Then let's create a Client. Start django shell: ``python manage.py shell``.

.. code:: python

    >>> from openid_provider.models import Client
    >>> c = Client(name='Some Client', client_id='123', client_secret='456', response_type='code', redirect_uris=['http://example.com/'])
    >>> c.save()

*******************
/authorize endpoint
*******************

Example of an OpenID Authentication Request using the ´´Authorization Code´´ flow.

.. code:: curl

    GET /openid/authorize?client_id=123&redirect_uri=http%3A%2F%2Fexample.com%2F&response_type=code&scope=openid%20profile%20email&state=abcdefgh HTTP/1.1
    Host: localhost:8000
    Cache-Control: no-cache
    Content-Type: application/x-www-form-urlencoded

****
Code
****

After the user accepts and authorizes the client application, the server redirects to:

.. code:: curl

    http://example.com/?code=5fb3b172913448acadce6b011af1e75e&state=abcdefgh

We extract the ``code`` param and use it to obtain access token.

***************
/token endpoint
***************

.. code:: curl

    POST /openid/token/ HTTP/1.1
    Host: localhost:8000
    Cache-Control: no-cache
    Content-Type: application/x-www-form-urlencoded

    client_id=123&client_secret=456&redirect_uri=http%253A%252F%252Fexample.com%252F&grant_type=authorization_code&code=[CODE]&state=abcdefgh

******************
/userinfo endpoint
******************

.. code:: curl

    POST /openid/userinfo/ HTTP/1.1
    Host: localhost:8000
    Authorization: Bearer [ACCESS_TOKEN]
