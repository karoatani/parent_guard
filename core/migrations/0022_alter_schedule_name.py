# Generated by Django 5.1.4 on 2025-01-18 02:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0021_alter_schedule_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='schedule',
            name='name',
            field=models.CharField(max_length=255),
        ),
    ]
