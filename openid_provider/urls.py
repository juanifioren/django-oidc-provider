from django.conf.urls import patterns, include, url
from django.views.decorators.csrf import csrf_exempt

from openid_provider.views import clients
from openid_provider.views import endpoints

urlpatterns = patterns('',

	url(r'^authorize/$', endpoints.AuthorizeView.as_view(), name='authorize'),
	url(r'^token/$', csrf_exempt(endpoints.TokenView.as_view()), name='token'),
	url(r'^userinfo/$', csrf_exempt(endpoints.userinfo), name='userinfo'),

	url(r'^login/$', 'django.contrib.auth.views.login', name='login'),
	url(r'^logout/$', 'django.contrib.auth.views.logout', name='logout'),

	url(r'^clients/$', clients.ClientListView.as_view(), name='clients'),

)