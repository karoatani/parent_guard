# Generated by Django 5.1.4 on 2025-01-18 03:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0022_alter_schedule_name'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='parentprofile',
            name='is_global_rules_applied',
        ),
        migrations.AddField(
            model_name='childprofile',
            name='is_global_rules_applied',
            field=models.BooleanField(default=True),
        ),
    ]
