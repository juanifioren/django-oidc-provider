from django.conf.urls import patterns, include, url
from django.views.decorators.csrf import csrf_exempt

from openid_provider.views import clients
from openid_provider.views import endpoints

urlpatterns = patterns('',

	url(r'^authorize/$', endpoints.AuthorizeView.as_view(), name='authorize'),
	url(r'^token/$', csrf_exempt(endpoints.TokenView.as_view()), name='token'),
	url(r'^userinfo/$', csrf_exempt(endpoints.userinfo), name='userinfo'),

	url(r'^login/$', 'django.contrib.auth.views.login', { 'template_name': 'openid_provider/login.html' }, name='login'),
	url(r'^logout/$', 'django.contrib.auth.views.logout', { 'template_name': 'openid_provider/logout.html' }, name='logout'),

	url(r'^clients/$', clients.ClientListView.as_view(), name='client_list'),
	url(r'^clients/(?P<pk>[\d]+)/$', clients.ClientDetailView.as_view(), name='client_detail'),

)