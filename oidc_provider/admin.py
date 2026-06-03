from hashlib import sha224
from random import randint
from uuid import uuid4

from django.contrib import admin
from django.contrib import messages
from django.forms import ModelForm
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from oidc_provider.lib.utils.client_credentials import hash_secret
from oidc_provider.lib.utils.sanitization import sanitize_client_id
from oidc_provider.models import Client
from oidc_provider.models import Code
from oidc_provider.models import RSAKey
from oidc_provider.models import Token


class ClientForm(ModelForm):
    class Meta:
        model = Client
        exclude = []

    def __init__(self, *args, **kwargs):
        super(ClientForm, self).__init__(*args, **kwargs)
        self.fields["client_id"].required = False
        self.fields["client_id"].widget.attrs["disabled"] = "true"
        self.fields["client_secret"].required = False
        self.fields["client_secret"].widget.attrs["disabled"] = "true"
        self.fields["jwt_alg"].required = False

    def clean_client_id(self):
        instance = getattr(self, "instance", None)
        if instance and instance.pk:
            # Sanitize existing client_id to remove any problematic characters
            return sanitize_client_id(instance.client_id)
        else:
            # Generate new client_id (digits only)
            return str(randint(1, 999999)).zfill(6)

    def clean_client_secret(self):
        """
        Generate and hash a new secret when creating a confidential client.

        The plaintext is stashed on the form so ``save_model`` can display it once
        via a one-time admin message. On update the existing hash is preserved.
        """
        instance = getattr(self, "instance", None)
        self._plaintext_secret = ""
        secret = ""

        if instance and instance.pk:
            if (self.cleaned_data["client_type"] == "confidential") and not instance.client_secret:
                self._plaintext_secret = sha224(uuid4().hex.encode()).hexdigest()
            elif (self.cleaned_data["client_type"] == "confidential") and instance.client_secret:
                secret = instance.client_secret
        else:
            if self.cleaned_data["client_type"] == "confidential":
                self._plaintext_secret = sha224(uuid4().hex.encode()).hexdigest()

        secret = hash_secret(self._plaintext_secret) if self._plaintext_secret else secret
        return secret


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    fieldsets = [
        [
            _(""),
            {
                "fields": (
                    "name",
                    "owner",
                    "client_type",
                    "response_types",
                    "_redirect_uris",
                    "jwt_alg",
                    "require_consent",
                    "reuse_consent",
                ),
            },
        ],
        [
            _("Credentials"),
            {
                "fields": ("client_id", "client_secret", "_scope"),
            },
        ],
        [
            _("Information"),
            {
                "fields": ("contact_email", "website_url", "terms_url", "logo", "date_created"),
            },
        ],
        [
            _("Session Management"),
            {
                "fields": ("_post_logout_redirect_uris",),
            },
        ],
    ]
    form = ClientForm
    list_display = ["name", "client_id", "response_type_descriptions", "date_created"]
    readonly_fields = ["date_created"]
    search_fields = ["name"]
    raw_id_fields = ["owner"]

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        plaintext = getattr(form, "_plaintext_secret", None)
        if plaintext:
            self.message_user(
                request,
                format_html(
                    "<strong>Client secret (copy now — this will not be shown again):</strong>"
                    "<br><code style='font-size:1.1em; user-select:all;'>{}</code>",
                    plaintext,
                ),
                level=messages.WARNING,
            )


@admin.register(Code)
class CodeAdmin(admin.ModelAdmin):
    raw_id_fields = ["user"]

    def has_add_permission(self, request):
        return False


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    raw_id_fields = ["user"]

    def has_add_permission(self, request):
        return False


@admin.register(RSAKey)
class RSAKeyAdmin(admin.ModelAdmin):
    readonly_fields = ["kid"]
