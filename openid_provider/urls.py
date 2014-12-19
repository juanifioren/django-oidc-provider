from django.conf.urls import patterns, include, url
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = patterns('',

	url(r'^authorize/$', views.AuthorizeView.as_view(), name='authorize'),
	url(r'^token/$', csrf_exempt(views.TokenView.as_view()), name='token'),
	url(r'^userinfo/$', csrf_exempt(views.userinfo), name='userinfo'),

)