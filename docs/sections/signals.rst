.. _signals:

Signals
#######

Use signals in your application to get notified when some actions occur.

For example::

    from django.dispatch import receiver

    from oidc_provider.signals import user_decline_consent


    @receiver(user_decline_consent)
    def my_callback(sender, **kwargs):
        print(kwargs)
        print('Ups! Some user has declined the consent.')

user_accept_consent
===================

Sent when a user accept the authorization page for some client.

user_decline_consent
====================

Sent when a user decline the authorization page for some client.
