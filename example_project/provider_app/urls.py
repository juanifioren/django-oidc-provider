from django.contrib.auth import views as auth_views
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.views.generic import TemplateView


urlpatterns = [
    url(r'^$', TemplateView.as_view(template_name='home.html'), name='home'),

    url(r'^', include('oidc_provider.urls', namespace='oidc_provider')),

    url(r'^admin/', include(admin.site.urls)),
]
