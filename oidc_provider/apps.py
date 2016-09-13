from django.apps import AppConfig
from django.contrib.auth import user_logged_out


def attach_user_logged_out(sender, **kwargs):
    """
    Receiver that attaches the user that just logged out to the current request, so that
    it can be accessed later in the request.
    """
    request = kwargs['request']
    user = kwargs['user']
    request.user_logged_out = user


class OIDCProviderConfig(AppConfig):
    name = 'oidc_provider'
    verbose_name = u'OpenID Connect Provider'

    user_logged_out.connect(attach_user_logged_out)
