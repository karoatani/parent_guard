# Generated by Django 5.1.4 on 2025-01-22 20:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0024_activitylog_action_activitylog_reason'),
    ]

    operations = [
        migrations.AlterField(
            model_name='childprofile',
            name='schedule',
            field=models.ManyToManyField(blank=True, null=True, related_name='child_profile', to='core.schedule'),
        ),
    ]
