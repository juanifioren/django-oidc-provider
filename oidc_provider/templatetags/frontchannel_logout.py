from django import template

from oidc_provider.lib.utils.common import get_site_url, get_issuer, get_user_sid
from oidc_provider.models import Token

register = template.Library()


@register.inclusion_tag('oidc_provider/logout_clients.html', takes_context=True)
def logout_clients(context):
    """
    Template tag which renders the iframe tags that will logout the user from Clients
    that requested to do so.
    """
    request = context.request
    user_logged_out = request.user_logged_out

    if user_logged_out is not None:
        site_url = get_site_url(request=request)
        iss = get_issuer(site_url=site_url, request=request)
        sid = get_user_sid(user_logged_out)

        return {
            'logout_urls': filter(
                lambda url: url,
                set(
                    map(
                        lambda token: token.client.get_frontchannel_logout_uri(iss, sid),
                        Token.objects.filter(user=user_logged_out)
                    )
                )
            )
        }
    else:
        return {
            'logout_urls': []
        }
