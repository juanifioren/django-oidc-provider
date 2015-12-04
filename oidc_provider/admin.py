from django.contrib import admin

from oidc_provider.models import Client, Code, Token


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    
    search_fields = ['name']


@admin.register(Code)
class CodeAdmin(admin.ModelAdmin):
    
    def has_add_permission(self, request):
        return False


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    
    def has_add_permission(self, request):
        return False
