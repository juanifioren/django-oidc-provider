.. _scopesclaims:

Scopes and Claims
#################

This subset of OpenID Connect defines a set of standard Claims. They are returned in the UserInfo Response.

The package comes with a setting called ``OIDC_USERINFO``, basically it refers to a function that will be called with ``claims`` (dict) and ``user`` (user instance). It returns the ``claims`` dict with all the claims populated.

List of all the ``claims`` keys grouped by scopes:

+--------------------+----------------+-----------------------+------------------------+
| profile            | email          | phone                 | address                |
+====================+================+=======================+========================+
| name               | email          | phone_number          | formatted              |
+--------------------+----------------+-----------------------+------------------------+
| given_name         | email_verified | phone_number_verified | street_address         |
+--------------------+----------------+-----------------------+------------------------+
| family_name        |                |                       | locality               |
+--------------------+----------------+-----------------------+------------------------+
| middle_name        |                |                       | region                 |
+--------------------+----------------+-----------------------+------------------------+
| nickname           |                |                       | postal_code            |
+--------------------+----------------+-----------------------+------------------------+
| preferred_username |                |                       | country                |
+--------------------+----------------+-----------------------+------------------------+
| profile            |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| picture            |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| website            |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| gender             |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| birthdate          |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| zoneinfo           |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| locale             |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| updated_at         |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+

How to populate standard claims
===============================

Somewhere in your Django ``settings.py``::

    OIDC_USERINFO = 'myproject.oidc_provider_settings.userinfo'


Then inside your ``oidc_provider_settings.py`` file create the function for the ``OIDC_USERINFO`` setting::

    def userinfo(claims, user):
        # Populate claims dict.
        claims['name'] = '{0} {1}'.format(user.first_name, user.last_name)
        claims['given_name'] = user.first_name
        claims['family_name'] = user.last_name
        claims['email'] = user.email
        claims['address']['street_address'] = '...'

        return claims

Now test an Authorization Request using these scopes ``openid profile email`` and see how user attributes are returned.

.. note::
    Please **DO NOT** add extra keys or delete the existing ones in the ``claims`` dict. If you want to add extra claims to some scopes you can use the ``OIDC_EXTRA_SCOPE_CLAIMS`` setting.

How to add custom scopes and claims
===================================

The ``OIDC_EXTRA_SCOPE_CLAIMS`` setting is used to add extra scopes specific for your app. Is just a class that inherit from ``oidc_provider.lib.claims.ScopeClaims``. You can create or modify scopes by adding this methods into it:

* ``info_scopename`` class property for setting the verbose name and description.
* ``scope_scopename`` method for returning some information related.

Let's say that you want add your custom ``foo`` scope for your OAuth2/OpenID provider. So when a client (RP) makes an Authorization Request containing ``foo`` in the list of scopes, it will be listed in the consent page (``templates/oidc_provider/authorize.html``) and then some specific claims like ``bar`` will be returned from the ``/userinfo`` response.

Somewhere in your Django ``settings.py``::

    OIDC_EXTRA_SCOPE_CLAIMS = 'yourproject.oidc_provider_settings.CustomScopeClaims'

Inside your oidc_provider_settings.py file add the following class::

    from django.utils.translation import ugettext as _
    from oidc_provider.lib.claims import ScopeClaims

    class CustomScopeClaims(ScopeClaims):

        info_foo = (
            _(u'Foo'),
            _(u'Some description for the scope.'),
        )

        def scope_foo(self):
            # self.user - Django user instance.
            # self.userinfo - Dict returned by OIDC_USERINFO function.
            # self.scopes - List of scopes requested.
            # self.client - Client requesting this claims.
            dic = {
                'bar': 'Something dynamic here',
            }

            return dic

        # If you want to change the description of the profile scope, you can redefine it.
        info_profile = (
            _(u'Profile'),
            _(u'Another description.'),
        )

.. note::
    If a field is empty or ``None`` inside the dictionary you return on the ``scope_scopename`` method, it will be cleaned from the response.
