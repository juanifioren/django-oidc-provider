.. _claims:

Standard Claims
###############

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

How to populate userinfo response
=================================

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
