# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0018_auto_20160908_1627'),
    ]

    operations = [
        migrations.AlterField(
            model_name='client',
            name='response_type',
            field=models.CharField(choices=[('code', 'code (Authorization Code Flow)'), ('id_token', 'id_token (Implicit Flow)'), ('id_token token', 'id_token token (Implicit Flow)'), ('code token', 'code token (Hybrid Flow)'), ('code id_token', 'code id_token (Hybrid Flow)'), ('code id_token token', 'code id_token token (Hybrid Flow)')], verbose_name='Response Type', max_length=30),
            preserve_default=True,
        ),
    ]
