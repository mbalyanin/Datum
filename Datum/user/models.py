from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from dateutil.relativedelta import relativedelta
from django.core.cache import cache

import pytz

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

     def get_viewed_profiles(self):
          """Возвращает ID просмотренных профилей"""
          return cache.get(f'viewed_{self.id}', [])

     def add_viewed_profile(self, profile_id):
          """Добавляет профиль в просмотренные"""
          viewed = self.get_viewed_profiles()
          viewed.append(profile_id)
          cache.set(f'viewed_{self.id}', viewed, 60 * 60 * 24 * 30)  # Храним 30 дней

     def get_liked_profiles(self):
          """Возвращает ID лайкнутых профилей"""
          return list(self.sent_likes.values_list('receiver_id', flat=True))

     def get_unread_notifications_count(self):
          if hasattr(self, 'notifications'):
               return self.notifications.filter(is_read=False).count()
          return 0

     def set_password(self, raw_password):
         try:
             validate_password(raw_password, self)
             super().set_password(raw_password)
             self.save()
             return True
         except ValidationError as e:
             return False
     @property
     def age(self):
          today = timezone.now().date()
          return relativedelta(today, self.birth_date).years

class Like(models.Model):
    sender = models.ForeignKey(User, related_name='sent_likes', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_likes', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('sender', 'receiver')

class MatchNotification(models.Model):
    user = models.ForeignKey(User, related_name='notifications', on_delete=models.CASCADE)
    matched_user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

class ChatRoom(models.Model):
    user1 = models.ForeignKey(User, related_name='chat_rooms1', on_delete=models.CASCADE)
    user2 = models.ForeignKey(User, related_name='chat_rooms2', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user1', 'user2')

class Message(models.Model):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    is_read = models.BooleanField(default=False)
    class Meta:
        ordering = ['timestamp']
