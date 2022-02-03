try:
    from django.urls import include, url
except ImportError:
    from django.urls import include, path

from django.contrib.auth.views import LoginView, LogoutView

from django.contrib import admin
from django.views.generic import TemplateView

urlpatterns = [
    path("", TemplateView.as_view(template_name="home.html"), name="home"),
    path("accounts/login/", LoginView.as_view(), name="login"),
    path("accounts/logout/", LogoutView.as_view(), name="logout"),
    path("", include("oidc_provider.urls", namespace="oidc_provider")),
    path("admin/", admin.site.urls),
]
