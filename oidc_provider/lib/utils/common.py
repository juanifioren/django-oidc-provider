from django.core.urlresolvers import reverse
from django.http import HttpResponse

from oidc_provider import settings

try:
    from urlparse import urlsplit, urlunsplit
except ImportError:
    from urllib.parse import urlsplit, urlunsplit


def cleanup_url_from_query_string(uri):
    """
    Function used to clean up the uri from any query string, used i.e. by endpoints to validate redirect_uri

    :param uri: URI to clean from query string
    :type uri: str
    :return: cleaned URI without query string
    """
    clean_uri = urlsplit(uri)
    clean_uri = urlunsplit(clean_uri._replace(query=''))
    return clean_uri


def redirect(uri):
    """
    Custom Response object for redirecting to a Non-HTTP url scheme.
    """
    response = HttpResponse('', status=302)
    response['Location'] = uri
    return response


def get_site_url(site_url=None, request=None):
    """
    Construct the site url.

    Orders to decide site url:
        1. valid `site_url` parameter
        2. valid `SITE_URL` in settings
        3. construct from `request` object
    """
    site_url = site_url or settings.get('SITE_URL')
    if site_url:
        return site_url
    elif request:
        return '{}://{}'.format(request.scheme, request.get_host())
    else:
        raise Exception('Either pass `site_url`, '
                        'or set `SITE_URL` in settings, '
                        'or pass `request` object.')

def get_issuer(site_url=None, request=None):
    """
    Construct the issuer full url. Basically is the site url with some path
    appended.
    """
    site_url = get_site_url(site_url=site_url, request=request)
    path = reverse('oidc_provider:provider_info') \
        .split('/.well-known/openid-configuration')[0]
    issuer = site_url + path

    return str(issuer)


def default_userinfo(claims, user):
    """
    Default function for setting OIDC_USERINFO.
    `claims` is a dict that contains all the OIDC standard claims.
    """
    return claims


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
