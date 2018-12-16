from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("oidc_provider", "0029_change_response_types_field_2_of_3"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="client",
            name="old_response_types",
        ),
        migrations.DeleteModel(
            name="ResponseType",
        ),
    ]
