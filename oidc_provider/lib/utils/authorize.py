from datetime import timedelta

from django.utils import timezone

try:
    from urllib import urlencode
    from urlparse import urlsplit, parse_qs, urlunsplit
except ImportError:
    from urllib.parse import urlsplit, parse_qs, urlunsplit, urlencode

from oidc_provider.models import UserConsent
from oidc_provider import settings


def strip_prompt_login(path):
    """
    Strips 'login' from the 'prompt' query parameter.
    """
    uri = urlsplit(path)
    query_params = parse_qs(uri.query)
    prompt_list = query_params.get('prompt', '')[0].split()
    if 'login' in prompt_list:
        prompt_list.remove('login')
        query_params['prompt'] = ' '.join(prompt_list)
    if not query_params['prompt']:
        del query_params['prompt']
    uri = uri._replace(query=urlencode(query_params, doseq=True))
    return urlunsplit(uri)


def default_update_or_create_user_consent(user, client, date_given, expires_at, scope, request):
    """
    WARNING: The api of this function is still experimental and may change at any time.

    Create (or update) and populate the UserConsent object.
    Return a saved UserConsent object and the created boolean.
    """
    user_consent, created = UserConsent.objects.update_or_create(
        user=user,
        client=client,
        defaults={
            'expires_at': expires_at,
            'date_given': date_given,
            'scope': scope,
        }
    )
    return user_consent, created


def update_or_create_user_consent(**kwargs):
    date_given = timezone.now()
    expires_at = date_given + timedelta(days=settings.get('OIDC_SKIP_CONSENT_EXPIRE'))
    kwargs['date_given'] = date_given
    kwargs['expires_at'] = expires_at
    return settings.get('OIDC_UPDATE_OR_CREATE_USER_CONSENT', import_str=True)(**kwargs)
