# Generated by Django 5.1.4 on 2025-01-14 16:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_browsingsession_date_created_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='browsingsession',
            name='date_created',
        ),
    ]
