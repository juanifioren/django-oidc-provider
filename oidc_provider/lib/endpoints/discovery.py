from django.core.urlresolvers import reverse

from oidc_provider import settings
from oidc_provider.lib.utils.common import get_issuer


class ProviderInfoEndpoint(object):

    @classmethod
    def create_response_dic(cls):
        dic = {}

        dic['issuer'] = get_issuer()

        SITE_URL = settings.get('SITE_URL')

        dic['authorization_endpoint'] = SITE_URL + reverse('oidc_provider:authorize')
        dic['token_endpoint'] = SITE_URL + reverse('oidc_provider:token')
        dic['userinfo_endpoint'] = SITE_URL + reverse('oidc_provider:userinfo')

        from oidc_provider.models import Client
        types_supported = [x[0] for x in Client.RESPONSE_TYPE_CHOICES]
        dic['response_types_supported'] = types_supported

        # TODO:
        #dic['jwks_uri'] = None

        # See: http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
        dic['subject_types_supported'] = ['public']

        return dic