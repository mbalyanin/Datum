# Generated by Django 5.1.7 on 2025-03-24 16:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0007_alter_user_username'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='mfa_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='mfa_secret',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
    ]
