from django.db import models
from django.conf import settings
from django.utils import timezone
import hashlib



class User(models.Model):
    name = models.CharField(max_length=20)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=200)
    is_active = models.BooleanField(default=False)

    def encrypt_password(self):
        temp = str(self.id) + str(self.password);
        self.password = hashlib.sha256(temp.encode()).hexdigest()
        print("저장된 비밀번호: (model)"+self.password)
        self.save()


