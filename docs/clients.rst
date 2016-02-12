.. _clients:

Clients
#######

Also known as Relying Parties (RP). User and client creation it's up to you. This is because is out of the scope in the core implementation of OIDC.
So, there are different ways to create your Clients. By displaying a HTML form or maybe if you have internal thrusted Clients you can create them programatically.

`Read more about client creation from OAuth2 spec <http://tools.ietf.org/html/rfc6749#section-2>`_

For your users, the tipical situation is that you provide them a login and a registration page.

If you want to test the provider without getting to deep into this topics you can:

Create a user with ``python manage.py createsuperuser`` and clients using Django admin:

.. image:: http://i64.tinypic.com/2dsfgoy.png
    :align: center

Or also you can create a client programmatically with Django shell ``python manage.py shell``::

    >>> from oidc_provider.models import Client
    >>> c = Client(name='Some Client', client_id='123', client_secret='456', response_type='code', redirect_uris=['http://example.com/'])
    >>> c.save()
