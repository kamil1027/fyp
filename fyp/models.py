from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

# Create your models here.
class User(models.Model):
    userid = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    passwords = models.CharField(max_length=100)
    email = models.EmailField()
    mfakey = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False, null=True)
    updated_at = models.DateTimeField(default=timezone.now, editable=False, null=True)
    
    def __str__(self):
        return f'{self.name} ({self.passwords})'

class Password(models.Model):
    passwordid = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    expiration_day = models.CharField(max_length=3)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(default=timezone.now, editable=False)

    def __str__(self):
        return self.name

class Directory(models.Model):
    directoryid = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(default=timezone.now, editable=False)

class Group(models.Model):
    groupid = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(default=timezone.now, editable=False)

class DirectoryGroup(models.Model):
    directorygroupid = models.AutoField(primary_key=True)
    groupid = models.ForeignKey(Group,on_delete=models.CASCADE)
    directoryid = models.ForeignKey(Directory,on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(default=timezone.now, editable=False)

class UserDirectory(models.Model):
    userdirectoryid = models.AutoField(primary_key=True)
    userid = models.ForeignKey(User, on_delete=models.CASCADE)
    directoryid = models.ForeignKey(Directory, on_delete=models.CASCADE)
    passwordid = models.ForeignKey(Password, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(default=timezone.now, editable=False)

class UserGroup(models.Model):
    usergroupid = models.AutoField(primary_key=True)
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    groupid = models.ForeignKey(Group,on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(default=timezone.now, editable=False)
