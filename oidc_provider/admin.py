from django.contrib import admin
from .models import Client, Code, Token, UserInfo

admin.site.register(Client)
admin.site.register(Code)
admin.site.register(Token)
admin.site.register(UserInfo)