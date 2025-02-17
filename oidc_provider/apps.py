from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class OIDCProviderConfig(AppConfig):

    name = 'oidc_provider'
    verbose_name = _(u'OpenID Connect Provider')
