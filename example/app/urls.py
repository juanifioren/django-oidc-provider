from django.contrib.auth import views as auth_views
from django.urls import include, re_path
from django.contrib import admin
from django.views.generic import TemplateView


urlpatterns = [
    re_path(r"^$", TemplateView.as_view(template_name='home.html'), name='home'),
    re_path(r"^accounts/login/$", auth_views.LoginView.as_view(template_name='login.html'), name='login'),  # noqa
    re_path(r"^accounts/logout/$", auth_views.LogoutView.as_view(next_page='/'), name='logout'),
    re_path(r"^", include('oidc_provider.urls', namespace='oidc_provider')),
    re_path(r"^admin/", admin.site.urls),
]
