from django.db import models
from django.conf import settings
from django.utils import timezone
import hashlib

class User(models.Model):
    name = models.CharField(max_length=20)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=200)
    tokens = models.CharField(max_length=1000, default="")
    is_active = models.BooleanField(default=False)




