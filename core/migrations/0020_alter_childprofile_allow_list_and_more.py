# Generated by Django 5.1.4 on 2025-01-18 01:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0019_parentprofile_default_daily_limit'),
    ]

    operations = [
        migrations.AlterField(
            model_name='childprofile',
            name='allow_list',
            field=models.ManyToManyField(blank=True, to='core.allowlist'),
        ),
        migrations.AlterField(
            model_name='childprofile',
            name='block_list',
            field=models.ManyToManyField(blank=True, to='core.blocklist'),
        ),
    ]
