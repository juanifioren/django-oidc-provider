from django.contrib.auth import views as auth_views
try:
    from django.urls import include, url
except ImportError:
    from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic import TemplateView


urlpatterns = [
    url(r'^$', TemplateView.as_view(template_name='home.html'), name='home'),
    url(r'^accounts/login/$', auth_views.login, {'template_name': 'login.html'}, name='login'),
    url(r'^accounts/logout/$', auth_views.logout, {'next_page': '/'}, name='logout'),
    url(r'^', include('oidc_provider.urls', namespace='oidc_provider')),
    url(r'^admin/', admin.site.urls),
]
