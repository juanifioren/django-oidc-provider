.. _userconsent:

User Consent
############

The package store some information after the user grant access to some client. For example, you can use the ``UserConsent`` model to list applications that the user have authorized access. Like Google does `here <https://security.google.com/settings/security/permissions>`_.

    >>> from oidc_provider.models import UserConsent
    >>> UserConsent.objects.filter(user__email='some@email.com')
    [<UserConsent: Example Client - some@email.com>]

Note: the ``UserConsent`` model is not included in the admin.


Properties
==========

* ``user``: Django user object.
* ``client``: Relying Party object.
* ``expires_at``: Expiration date of the consent.
* ``scope``: Scopes authorized.
* ``date_given``: Date of the authorization.
