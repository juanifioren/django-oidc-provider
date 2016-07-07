.. _claims:

Standard Claims
###############

This subset of OpenID Connect defines a set of standard Claims. They are returned in the UserInfo Response.

The package comes with a setting called ``OIDC_USERINFO``, basically it refers to a class that MUST have a class-method named ``get_by_user``, this will be called with a Django ``User`` instance and returns an object with all the claims of the user as attributes.

List of all the attributes grouped by scopes:

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

Somewhere in your Django ``settings.py``::

    OIDC_USERINFO = 'myproject.oidc_provider_settings.userinfo'


Then create the function for the ``OIDC_USERINFO`` setting::

    def userinfo(claims, user):

        claims['name'] = '{0} {1}'.format(user.first_name, user.last_name)
        claims['given_name'] = user.first_name
        claims['family_name'] = user.last_name
        claims['email'] = user.email
        claims['address']['street_address'] = '...'

        return claims

.. note::
    Please **DO NOT** add extra keys or delete the existing ones in the ``claims`` dict. If you want to add extra claims to some scopes you can use the ``OIDC_EXTRA_SCOPE_CLAIMS`` setting.
