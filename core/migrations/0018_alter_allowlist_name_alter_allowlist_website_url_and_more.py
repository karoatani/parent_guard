# Generated by Django 5.1.4 on 2025-01-17 14:33

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0017_remove_childprofile_is_global_rules_applied_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='allowlist',
            name='name',
            field=models.CharField(max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='allowlist',
            name='website_url',
            field=models.URLField(unique=True),
        ),
        migrations.AlterField(
            model_name='childprofile',
            name='parent',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='child_profile', to='core.parentprofile'),
        ),
    ]
