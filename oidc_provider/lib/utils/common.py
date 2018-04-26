from hashlib import sha224

import django
from django.http import HttpResponse

from oidc_provider import settings


if django.VERSION >= (1, 11):
    from django.urls import reverse
else:
    from django.core.urlresolvers import reverse


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
    path = reverse('oidc_provider:provider-info') \
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


def default_after_end_session_hook(
        request, id_token=None, post_logout_redirect_uri=None,
        state=None, client=None, next_page=None):
    """
    Default function for setting OIDC_AFTER_END_SESSION_HOOK.

    :param request: Django request object
    :type request: django.http.HttpRequest

    :param id_token: token passed by `id_token_hint` url query param.
                     Do NOT trust this param or validate token
    :type id_token: str

    :param post_logout_redirect_uri: redirect url from url query param.
                                     Do NOT trust this param
    :type post_logout_redirect_uri: str

    :param state: state param from url query params
    :type state: str

    :param client: If id_token has `aud` param and associated Client exists,
        this is an instance of it - do NOT trust this param
    :type client: oidc_provider.models.Client

    :param next_page: calculated next_page redirection target
    :type next_page: str
    :return:
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


def default_introspection_processing_hook(introspection_response, client, id_token):
    """
    Hook to customise the returned data from the token introspection endpoint
    :param introspection_response:
    :param client:
    :param id_token:
    :return:
    """
    return introspection_response


def get_browser_state_or_default(request):
    """
    Determine value to use as session state.
    """
    key = (request.session.session_key or
           settings.get('OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY'))
    return sha224(key.encode('utf-8')).hexdigest()


def run_processing_hook(subject, hook_settings_name, **kwargs):
    processing_hook = settings.get(hook_settings_name)
    if isinstance(processing_hook, (list, tuple)):
        for hook in processing_hook:
            subject = settings.import_from_str(hook)(subject, **kwargs)
    else:
        subject = settings.import_from_str(processing_hook)(subject, **kwargs)
    return subject
