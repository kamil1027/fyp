# Generated by Django 5.1.3 on 2024-11-12 03:40

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Directory',
            fields=[
                ('directoryid', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
            ],
        ),
        migrations.CreateModel(
            name='Group',
            fields=[
                ('groupid', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('userid', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('passwords', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('mfakey', models.CharField(max_length=255, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False, null=True)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now, editable=False, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='DirectoryGroup',
            fields=[
                ('directorygroupid', models.AutoField(primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('directoryid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='fyp.directory')),
                ('groupid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='fyp.group')),
            ],
        ),
        migrations.CreateModel(
            name='Password',
            fields=[
                ('passwordid', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=100)),
                ('expiration_day', models.CharField(max_length=3)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('created_by', models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='fyp.user')),
            ],
        ),
        migrations.AddField(
            model_name='group',
            name='created_by',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='fyp.user'),
        ),
        migrations.AddField(
            model_name='directory',
            name='created_by',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='fyp.user'),
        ),
        migrations.CreateModel(
            name='UserDirectory',
            fields=[
                ('userdirectoryid', models.AutoField(primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('directoryid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='fyp.directory')),
                ('passwordid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='fyp.password')),
                ('userid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='fyp.user')),
            ],
        ),
        migrations.CreateModel(
            name='UserGroup',
            fields=[
                ('usergroupid', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('groupid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='fyp.group')),
                ('userid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='fyp.user')),
            ],
        ),
    ]
