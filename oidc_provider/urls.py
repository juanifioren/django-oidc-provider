from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from oidc_provider import views


urlpatterns = [
    url(r'^authorize/?$', views.AuthorizeView.as_view(), name='authorize'),
    url(r'^token/?$', csrf_exempt(views.TokenView.as_view()), name='token'),
    url(r'^userinfo/?$', csrf_exempt(views.userinfo), name='userinfo'),
    url(r'^logout/?$', views.LogoutView.as_view(), name='logout'),

    url(r'^\.well-known/openid-configuration/?$', views.ProviderInfoView.as_view(), name='provider_info'),
    url(r'^jwks/?$', views.JwksView.as_view(), name='jwks'),
]
