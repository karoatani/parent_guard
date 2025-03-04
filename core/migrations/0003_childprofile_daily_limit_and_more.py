# Generated by Django 5.1.4 on 2025-01-12 14:00

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_alter_account_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='childprofile',
            name='daily_limit',
            field=models.PositiveIntegerField(default=0, validators=[django.core.validators.MinValueValidator(0)]),
        ),
        migrations.AlterField(
            model_name='childprofile',
            name='device_id',
            field=models.CharField(max_length=400, unique=True),
        ),
    ]
