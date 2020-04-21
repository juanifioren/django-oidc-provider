from django.contrib.auth import views as auth_views
try:
    from django.urls import include, url
except ImportError:
    from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic import TemplateView
from django.urls import re_path


urlpatterns = [
    re_path(r'^$', TemplateView.as_view(template_name='home.html'), name='home'),
    re_path(r'^accounts/login/$', auth_views.LoginView, {'template_name': 'login.html'}, name='login'),
    re_path(r'^accounts/logout/$', auth_views.LogoutView, {'next_page': '/'}, name='logout'),
    re_path(r'^', include('oidc_provider.urls', namespace='oidc_provider')),
    re_path(r'^admin/', admin.site.urls),
]
