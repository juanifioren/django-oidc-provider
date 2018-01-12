# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings

from oidc_provider import settings as oidc_settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('oidc_provider', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserConsent',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('expires_at', models.DateTimeField()),
                ('_scope', models.TextField(default=b'')),
                ('client', models.ForeignKey(to=oidc_settings.get('OIDC_CLIENT_MODEL'), on_delete=models.CASCADE)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model,),
        ),
    ]
