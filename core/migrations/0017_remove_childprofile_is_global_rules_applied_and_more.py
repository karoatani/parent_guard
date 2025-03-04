# Generated by Django 5.1.4 on 2025-01-17 12:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0016_remove_schedule_child_profile_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='childprofile',
            name='is_global_rules_applied',
        ),
        migrations.AddField(
            model_name='childprofile',
            name='is_allowed_list',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='parentprofile',
            name='allow_list',
            field=models.ManyToManyField(to='core.allowlist'),
        ),
        migrations.AddField(
            model_name='parentprofile',
            name='block_list',
            field=models.ManyToManyField(to='core.blocklist'),
        ),
        migrations.AddField(
            model_name='parentprofile',
            name='is_global_rules_applied',
            field=models.BooleanField(default=True),
        ),
    ]
