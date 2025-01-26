# Generated by Django 5.1.4 on 2025-01-17 12:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0015_schedule_child_profile_alter_childprofile_schedule'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='schedule',
            name='child_profile',
        ),
        migrations.AlterField(
            model_name='childprofile',
            name='schedule',
            field=models.ManyToManyField(related_name='child_profile', to='core.schedule'),
        ),
    ]
