.. _relyingparties:

Relying Parties
###############

Relying Parties (RP) creation it's up to you. This is because is out of the scope in the core implementation of OIDC.
So, there are different ways to create your Clients (RP). By displaying a HTML form or maybe if you have internal thrusted Clients you can create them programatically.

OAuth defines two client types, based on their ability to maintain the confidentiality of their client credentials:

* ``confidential``: Clients capable of maintaining the confidentiality of their credentials (e.g., client implemented on a secure server with restricted access to the client credentials).
* ``public``: Clients incapable of maintaining the confidentiality of their credentials (e.g., clients executing on the device used by the resource owner, such as an installed native application or a web browser-based application), and incapable of secure client authentication via any other means.

Using the admin
===============

We suggest you to use Django admin to easily manage your clients: 

.. image:: ../images/client_creation.png
    :align: center

For re-generating ``client_secret``, when you are in the Client editing view, select "Client type" to be ``public``. Then after saving, select back to be ``confidential`` and save again.

Custom view
===========

If for some reason you need to create your own view to manage them, you can grab the form class that the admin makes use of. Located in ``oidc_provider.admin.ClientForm``.

Some built-in logic that comes with it:

* Automatic ``client_id`` and ``client_secret`` generation.
* Empty ``client_secret`` when ``client_type`` is equal to ``public``.

Programmatically
================

You can create a Client programmatically with Django shell ``python manage.py shell``::

    >>> from oidc_provider.models import Client
    >>> c = Client(name='Some Client', client_id='123', client_secret='456', response_type='code', redirect_uris=['http://example.com/'])
    >>> c.save()

`Read more about client creation from OAuth2 spec <http://tools.ietf.org/html/rfc6749#section-2>`_