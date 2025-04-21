from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

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

     mfa_secret = models.CharField(max_length=16, blank=True, null=True)
     mfa_enabled = models.BooleanField(default=False)

     email_verify = models.BooleanField(default=False)

     USERNAME_FIELD = 'email'
     REQUIRED_FIELDS = ['username']

     GENDER_CHOICES = [
          ('M', 'Мужской'),
          ('F', 'Женский')
     ]
     SEEKING_CHOICES = [
          ('M', 'Мужчин'),
          ('F', 'Женщин'),
          ('A', 'Всех'),
     ]

     # Основная информация
     gender = models.CharField(max_length=1, choices=GENDER_CHOICES, verbose_name='Пол', null=True, blank=True)
     name = models.CharField(max_length=128, blank=True, verbose_name='Имя')
     birth_date = models.DateField(null=True, blank=True, verbose_name='Дата рождения')
     city = models.CharField(max_length=100, blank=True, verbose_name='Город')

     # Информация для поиска
     seeking = models.CharField(max_length=1, choices=SEEKING_CHOICES, default='A', verbose_name='Ищу')
     min_age = models.PositiveIntegerField(default=18, verbose_name='Минимальный возраст партнера')
     max_age = models.PositiveIntegerField(default=60, verbose_name='Максимальный возраст партнера')

     # О себе
     bio = models.TextField(max_length=2000, blank=True, verbose_name='О себе')
     hobbies = models.CharField(max_length=255, blank=True, verbose_name='Хобби')
     avatar = models.ImageField(upload_to='avatars/', blank=True, null=True, verbose_name='Аватар')

     # Системные поля
     profile_complete = models.BooleanField(default=False, verbose_name='Анкета заполнена')

     @property
     def age(self):
          today = timezone.now().date()
          born = self.birth_date
          print(born)
          age = today.year - born.year
          if (today.month, today.day) < (born.month, born.day):
               age -= 1

          return age