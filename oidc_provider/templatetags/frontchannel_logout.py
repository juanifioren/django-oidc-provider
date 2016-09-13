import logging

from django import template

from oidc_provider.lib.utils.common import get_site_url, get_issuer, get_user_sid
from oidc_provider.lib.utils.user import get_authorized_clients


logger = logging.getLogger(__name__)
register = template.Library()


@register.inclusion_tag('oidc_provider/logout_clients.html', takes_context=True)
def logout_clients(context, user_logged_out=None, **kwargs):
    """
    Template tag which renders the iframe tags that will logout the user from Clients
    that requested to do so.
    """

    if user_logged_out:
        site_url = get_site_url(request=context.request)
        iss = get_issuer(site_url=site_url, request=context.request)
        sid = get_user_sid(user_logged_out)

        return {
            'logout_urls':
                filter(
                    lambda url: url,
                    map(
                        lambda client: client.get_frontchannel_logout_uri(iss, sid),
                        get_authorized_clients(user_logged_out)
                    )
                )
        }
    else:
        logger.warn(
            '`logout_clients` tag included but user to logout not found.'
        )
        return {
            'logout_urls': []
        }
