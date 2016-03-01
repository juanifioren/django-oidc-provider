from django.core.urlresolvers import reverse
from django.http import HttpResponse

from oidc_provider import settings


def redirect(uri):
    """
    Custom Response object for redirecting to a Non-HTTP url scheme.
    """
    response = HttpResponse('', status=302)
    response['Location'] = uri
    return response


def get_issuer():
    """
    Construct the issuer full url. Basically is the site url with some path
    appended.
    """
    site_url = settings.get('SITE_URL')
    path = reverse('oidc_provider:provider_info') \
        .split('/.well-known/openid-configuration')[0]
    issuer = site_url + path

    return issuer


class DefaultUserInfo(object):
    """
    Default class for setting OIDC_USERINFO.
    """

    @classmethod
    def get_by_user(cls, user):
        return None


def default_sub_generator(user):
    """
    Default function for setting OIDC_IDTOKEN_SUB_GENERATOR.
    """
    return str(user.id)


def default_after_userlogin_hook(request, user, client):
    """
    Default function for setting OIDC_AFTER_USERLOGIN_HOOK.
    """
    return None

def default_idtoken_processing_hook(id_token, user):
    """
    Hook to perform some additional actions ti `id_token` dictionary just before serialization.

    :param id_token: dictionary contains values that going to be serialized into `id_token`
    :type id_token: dict

    :param user: user for whom id_token is generated
    :type user: User

    :return: custom modified dictionary of values for `id_token`
    :rtype dict
    """
    return id_token
