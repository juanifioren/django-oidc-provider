# -*- coding: utf-8 -*-
# Generated by Django 1.11.23 on 2019-08-08 13:14
from __future__ import unicode_literals

from django.db import migrations, models


def migrate_response_type(apps, schema_editor):
    # ensure we get proper, versioned model with the deleted response_type field;
    # importing directly yields the latest without response_type
    ResponseType = apps.get_model('oidc_provider', 'ResponseType')
    Client = apps.get_model('oidc_provider', 'Client')
    response_type = ResponseType.objects.create(
        value='password', description='password (Password grant type)')
    # Assigning password response_type to all clients for backward compatibility
    for client in Client.objects.all():
        client.response_types.add(response_type)


def migrate_response_type_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0026_client_multiple_response_types'),
    ]

    operations = [
        migrations.AlterField(
            model_name='responsetype',
            name='value',
            field=models.CharField(choices=[('code', 'code (Authorization Code Flow)'), ('id_token', 'id_token (Implicit Flow)'), ('id_token token', 'id_token token (Implicit Flow)'), ('code token', 'code token (Hybrid Flow)'), ('code id_token', 'code id_token (Hybrid Flow)'), ('code id_token token', 'code id_token token (Hybrid Flow)'), ('password', 'password (Password grant type)')], max_length=30, unique=True, verbose_name='Response Type Value'),
        ),
        migrations.RunPython(migrate_response_type, migrate_response_type_reverse),
    ]
