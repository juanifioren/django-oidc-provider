from django.contrib.auth import views as auth_views
from django.conf.urls import patterns, include, url
from django.contrib import admin


urlpatterns = patterns('',
	url(r'^accounts/login/$', auth_views.login, {'template_name': 'accounts/login.html'}, name='login'),

    url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),

    url(r'^admin/', include(admin.site.urls)),
)
