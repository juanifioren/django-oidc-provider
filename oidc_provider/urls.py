try:
    from django.urls import url
except ImportError:
    from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt

from oidc_provider import (
    settings,
    views,
)

app_name = 'oidc_provider'
urlpatterns = [
    url(r'^authorize/?$', views.AuthorizeView.as_view(), name='authorize'),
    url(r'^token/?$', csrf_exempt(views.TokenView.as_view()), name='token'),
    url(r'^userinfo/?$', csrf_exempt(views.userinfo), name='userinfo'),
    url(r'^end-session/?$', views.EndSessionView.as_view(), name='end-session'),

    url(r'^\.well-known/openid-configuration/?$', views.ProviderInfoView.as_view(), name='provider-info'),
    url(r'^jwks/?$', views.JwksView.as_view(), name='jwks'),
]

if settings.get('OIDC_SESSION_MANAGEMENT_ENABLE'):
    urlpatterns += [
        url(r'^check-session-iframe/?$', views.CheckSessionIframeView.as_view(), name='check-session-iframe'),
    ]
