# Generated by Django 2.0.13 on 2020-01-17 01:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_auto_20200115_0156'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='tokens',
        ),
    ]
