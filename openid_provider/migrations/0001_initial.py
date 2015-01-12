# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(default=b'', max_length=100)),
                ('client_id', models.CharField(unique=True, max_length=255)),
                ('client_secret', models.CharField(unique=True, max_length=255)),
                ('client_type', models.CharField(max_length=20, choices=[(b'confidential', b'Confidential'), (b'public', b'Public')])),
                ('response_type', models.CharField(max_length=30, choices=[(b'code', b'code (Authorization Code Flow)'), (b'id_token', b'id_token (Implicit Flow)'), (b'id_token token', b'id_token token (Implicit Flow)')])),
                ('_scope', models.TextField(default=b'')),
                ('_redirect_uris', models.TextField(default=b'')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Code',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('code', models.CharField(unique=True, max_length=255)),
                ('expires_at', models.DateTimeField()),
                ('_scope', models.TextField(default=b'')),
                ('client', models.ForeignKey(to='openid_provider.Client')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('access_token', models.CharField(unique=True, max_length=255)),
                ('expires_at', models.DateTimeField()),
                ('_scope', models.TextField(default=b'')),
                ('_id_token', models.TextField()),
                ('client', models.ForeignKey(to='openid_provider.Client')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserInfo',
            fields=[
                ('user', models.OneToOneField(primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('given_name', models.CharField(default=b'', max_length=255)),
                ('family_name', models.CharField(default=b'', max_length=255)),
                ('middle_name', models.CharField(default=b'', max_length=255)),
                ('nickname', models.CharField(default=b'', max_length=255)),
                ('preferred_username', models.CharField(default=b'', max_length=255)),
                ('profile', models.URLField(default=b'')),
                ('picture', models.URLField(default=b'')),
                ('website', models.URLField(default=b'')),
                ('email_verified', models.BooleanField(default=False)),
                ('gender', models.CharField(default=b'', max_length=100)),
                ('birthdate', models.DateField()),
                ('zoneinfo', models.CharField(default=b'', max_length=100)),
                ('locale', models.CharField(default=b'', max_length=100)),
                ('phone_number', models.CharField(default=b'', max_length=255)),
                ('phone_number_verified', models.BooleanField(default=False)),
                ('address_formatted', models.CharField(default=b'', max_length=255)),
                ('address_street_address', models.CharField(default=b'', max_length=255)),
                ('address_locality', models.CharField(default=b'', max_length=255)),
                ('address_region', models.CharField(default=b'', max_length=255)),
                ('address_postal_code', models.CharField(default=b'', max_length=255)),
                ('address_country', models.CharField(default=b'', max_length=255)),
                ('updated_at', models.DateTimeField()),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='token',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='code',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='client',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
            preserve_default=True,
        ),
    ]
