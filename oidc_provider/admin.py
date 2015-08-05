from django.contrib import admin

from oidc_provider.models import Client, Code, Token


admin.site.register(Client)
admin.site.register(Code)
admin.site.register(Token)
