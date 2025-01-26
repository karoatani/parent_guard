# Generated by Django 5.1.4 on 2025-01-19 18:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0023_remove_parentprofile_is_global_rules_applied_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='activitylog',
            name='action',
            field=models.CharField(choices=[('allowed', 'Allowed'), ('blocked', 'Blocked')], default='', max_length=20),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='activitylog',
            name='reason',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
    ]
