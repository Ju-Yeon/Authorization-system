# Generated by Django 2.0.13 on 2020-01-14 16:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_user_tokens'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='if_active',
            field=models.BooleanField(default=False),
        ),
    ]
