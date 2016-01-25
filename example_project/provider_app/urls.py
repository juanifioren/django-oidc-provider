from django.contrib.auth import views as auth_views
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.views.generic import TemplateView


urlpatterns = [
    url(r'^$', TemplateView.as_view(template_name='home.html'), name='home'),
    url(r'^accounts/login/$', auth_views.login, { 'template_name': 'login.html' }, name='login'),
    url(r'^accounts/logout/$', auth_views.logout, { 'next_page': '/' }, name='logout'),

    url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),

    url(r'^admin/', include(admin.site.urls)),
]
