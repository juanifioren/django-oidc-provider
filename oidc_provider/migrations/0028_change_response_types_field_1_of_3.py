from django.db import migrations
from django.db import models


class Migration(migrations.Migration):
    dependencies = [
        ("oidc_provider", "0027_alter_rsakey_options"),
    ]

    operations = [
        migrations.RenameField(
            model_name="client",
            old_name="response_types",
            new_name="old_response_types",
        ),
        migrations.AddField(
            model_name="client",
            name="response_types",
            field=models.JSONField(default=list),
        ),
    ]
