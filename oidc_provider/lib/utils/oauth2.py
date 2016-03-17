import logging
import re

from django.http import HttpResponse

from oidc_provider.lib.errors import BearerTokenError
from oidc_provider.models import Token


logger = logging.getLogger(__name__)


def extract_access_token(request):
    """
    Get the access token using Authorization Request Header Field method.
    Or try getting via GET.
    See: http://tools.ietf.org/html/rfc6750#section-2.1

    Return a string.
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')

    if re.compile('^Bearer\s{1}.+$').match(auth_header):
        access_token = auth_header.split()[1]
    else:
        access_token = request.GET.get('access_token', '')

    return access_token


def protected_resource_view(scopes=[]):
    """
    View decorator. The client accesses protected resources by presenting the
    access token to the resource server.
    https://tools.ietf.org/html/rfc6749#section-7
    """
    def wrapper(view):
        def view_wrapper(request,  *args, **kwargs):
            access_token = extract_access_token(request)

            try:
                try:
                    kwargs['token'] = Token.objects.get(access_token=access_token)
                except Token.DoesNotExist:
                    logger.debug('[UserInfo] Token does not exist: %s', access_token)
                    raise BearerTokenError('invalid_token')

                if kwargs['token'].has_expired():
                    logger.debug('[UserInfo] Token has expired: %s', access_token)
                    raise BearerTokenError('invalid_token')

                if not set(scopes).issubset(set(kwargs['token'].scope)):
                    logger.debug('[UserInfo] Missing openid scope.')
                    raise BearerTokenError('insufficient_scope')
            except (BearerTokenError) as error:
                response = HttpResponse(status=error.status)
                response['WWW-Authenticate'] = 'error="{0}", error_description="{1}"'.format(error.code, error.description)
                return response

            return view(request,  *args, **kwargs)

        return view_wrapper

    return wrapper
