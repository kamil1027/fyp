# Generated by Django 5.1.3 on 2025-01-22 08:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fyp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='password',
            name='nonce',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
