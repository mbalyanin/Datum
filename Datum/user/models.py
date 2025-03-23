from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

# Create your models here.


class User(AbstractUser):
     email = models.EmailField(
          _('email address'),
          unique=True,
     )

     username = models.CharField(
          _('username'),
          max_length=150,
          blank=True,  # Поле может быть пустым
          null=True,  # Поле может быть NULL в базе данных
          unique=False,  # Убираем уникальность
     )

     email_verify = models.BooleanField(default=False)

     USERNAME_FIELD = 'email'
     REQUIRED_FIELDS = []
