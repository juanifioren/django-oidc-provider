from django.contrib import admin

from oidc_provider.models import Client, Code, Token, UserInfo


admin.site.register(Client)
admin.site.register(Code)
admin.site.register(Token)
admin.site.register(UserInfo)