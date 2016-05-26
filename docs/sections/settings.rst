.. _settings:

Settings
########

Customize your provider so fit your project needs.

LOGIN_URL
=========

REQUIRED. ``str``. Used to log the user in. `Read more in Django docs <https://docs.djangoproject.com/en/1.7/ref/settings/#login-url>`_

``str``. Default is ``/accounts/login/``.

SITE_URL
========

OPTIONAL. ``str``. The OP server url.

If not specified will be automatically generated using ``request.scheme`` and ``request.get_host()``.

For example ``http://localhost:8000``.

OIDC_AFTER_USERLOGIN_HOOK
=========================

OPTIONAL. ``str``. A string with the location of your function. Provide a way to plug into the process after the user has logged in, typically to perform some business logic.

Default is::

    def default_hook_func(request, user, client):
        return None

Return ``None`` if you want to continue with the flow.

The typical situation will be checking some state of the user or maybe redirect him somewhere.
With request you have access to all OIDC parameters. Remember that if you redirect the user to another place then you need to take him back to the authorize endpoint (use ``request.get_full_path()`` as the value for a "next" parameter).

OIDC_CODE_EXPIRE
================

OPTIONAL. ``int``. Code object expiration after been delivered.

Expressed in seconds. Default is ``60*10``.

OIDC_EXTRA_SCOPE_CLAIMS
=======================

OPTIONAL. ``str``. A string with the location of your class. Default is ``oidc_provider.lib.claims.AbstractScopeClaims``.

Used to add extra scopes specific for your app. This class MUST inherit ``AbstractScopeClaims``.

OpenID Connect Clients will use scope values to specify what access privileges are being requested for Access Tokens.

`Here <http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims>`_ you have the standard scopes defined by the protocol.

Check out an example of how to implement it::

    from oidc_provider.lib.claims import AbstractScopeClaims

    class MyAppScopeClaims(AbstractScopeClaims):

        def setup(self):
            # Here you can load models that will be used
            # in more than one scope for example.
            # print self.user
            # print self.scopes
            try:
                self.some_model = SomeModel.objects.get(user=self.user)
            except SomeModel.DoesNotExist:
                # Create an empty model object.
                self.some_model = SomeModel()

        def scope_books(self, user):

            # Here you can search books for this user.

            dic = {
                'books_readed': books_readed_count,
            }

            return dic

You can create our own scopes using the convention:

``def scope_SCOPENAMEHERE(self, user):``

If a field is empty or ``None`` will be cleaned from the response.

OIDC_IDTOKEN_EXPIRE
===================

OPTIONAL. ``int``. Token object expiration after been delivered.

Expressed in seconds. Default is ``60*10``.

OIDC_IDTOKEN_PROCESSING_HOOK
============================

OPTIONAL. ``str`` or ``(list, tuple)``.

A string with the location of your function hook or ``list`` or ``tuple`` with hook functions.
Here you can add extra dictionary values specific for your app into id_token.

The ``list`` or ``tuple`` is useful when You want to set multiple hooks, i.e. one for permissions and second for some special field.

The function receives a ``id_token`` dictionary and ``user`` instance 
and returns it with additional fields.

Default is::

    def default_idtoken_processing_hook(id_token, user):

        return id_token

OIDC_IDTOKEN_SUB_GENERATOR
==========================

OPTIONAL. ``str``. A string with the location of your function. ``sub`` is a locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client.

The function receives a ``user`` object and returns a unique ``string`` for the given user.

Default is::

    def default_sub_generator(user):

        return str(user.id)

OIDC_SKIP_CONSENT_ALWAYS
========================

OPTIONAL. ``bool``. If enabled, the Server will NEVER ask the user for consent.

Default is ``False``.

OIDC_SKIP_CONSENT_ENABLE
========================

OPTIONAL. ``bool``. If enabled, the Server will save the user consent given to a specific client, so that user won't be prompted for the same authorization multiple times.

Default is ``True``.

OIDC_SKIP_CONSENT_EXPIRE
========================

OPTIONAL. ``int``. User consent expiration after been granted.

Expressed in days. Default is ``30*3``.

OIDC_TOKEN_EXPIRE
=================

OPTIONAL. ``int``. Token object expiration after been created.

Expressed in seconds. Default is ``60*60``.

OIDC_USERINFO
=============

OPTIONAL. ``str``. A string with the location of your class. Read **Standard Claims** section.
