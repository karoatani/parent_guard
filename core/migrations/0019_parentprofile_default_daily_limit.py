# Generated by Django 5.1.4 on 2025-01-18 00:34

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0018_alter_allowlist_name_alter_allowlist_website_url_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='parentprofile',
            name='default_daily_limit',
            field=models.PositiveIntegerField(default=0, validators=[django.core.validators.MinValueValidator(0)]),
        ),
    ]
