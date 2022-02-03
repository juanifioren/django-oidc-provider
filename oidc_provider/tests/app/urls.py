from django.contrib.auth import views as auth_views

try:
    from django.urls import include, url
except ImportError:
    from django.urls import include, path

from django.contrib import admin
from django.views.generic import TemplateView

urlpatterns = [
    path('', TemplateView.as_view(template_name="home.html"), name="home"),
    path(
        'accounts/login/',
        auth_views.LoginView.as_view(template_name="accounts/login.html"),
        name="login",
    ),
    path(
        'accounts/logout/',
        auth_views.LogoutView.as_view(template_name="accounts/logout.html"),
        name="logout",
    ),
    path('openid/', include("oidc_provider.urls", namespace="oidc_provider")),
    path('admin/', admin.site.urls),
]
