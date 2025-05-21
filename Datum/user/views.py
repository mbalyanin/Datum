import io
import logging
import base64
from datetime import datetime

from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth.decorators import login_required
from .forms import ProfileForm
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from .forms import UserCreationForm, AuthenticationForm
from django.shortcuts import redirect
from .utils import send_email_for_verify
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.contrib import messages
from datetime import date
from django.core.cache import cache
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q, Count
from dateutil.relativedelta import relativedelta
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404
import pyotp
import qrcode

from .models import Like, MatchNotification, Message

# Create your views here.


User = get_user_model()

class ProfileView(LoginRequiredMixin, APIView):
    template_name = 'user/profile.html'
    login_url = '/user/login/'
    redirect_field_name = 'next'

    @swagger_auto_schema(
        operation_description="View profile with MFA QR code generation.",
        responses={200: 'Returns rendered profile page with QR code.'}
    )
    def get(self, request):
        user = request.user
        if not user.mfa_secret:
            user.mfa_secret = pyotp.random_base32()
            user.save()

        otp_uri = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(
            name=user.email,
            issuer_name="Datum"
        )
        qr = qrcode.make(otp_uri)
        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")

        buffer.seek(0)
        qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")

        qr_code_data_uri = f"data:image/png;base64,{qr_code}"
        return render(request, self.template_name, {"qrcode": qr_code_data_uri})


class SignUpView(APIView):
    template_name = 'registration/signup.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:  # Если пользователь уже вошёл
            return redirect('profile')  # Перенаправляем на профиль
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Display signup form.",
        responses={200: 'Signup form page.'}
    )
    def get(self, request):
        context = {
            'form': UserCreationForm()
        }
        return render(request, self.template_name, context)

    @swagger_auto_schema(
        operation_description="Submit signup form.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password1': openapi.Schema(type=openapi.TYPE_STRING),
                'password2': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['email', 'password1', 'password2']
        ),
        responses={200: 'Signup success or form error'}
    )
    def post(self, request):
        form = UserCreationForm(request.POST)

        if form.is_valid():
            form.save()
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=email, password=password)
            send_email_for_verify(request, user)
            return render(request, 'registration/confirm_email.html')
        context = {
            'form': form
        }
        return render(request, self.template_name, context)

class EmailVerify(APIView):
    @swagger_auto_schema(
        operation_description="Verify email using uid and token.",
        responses={302: 'Redirect to home or invalid verify page'}
    )
    def get(self, request, uidb64, token):
        user = self.get_user(uidb64)

        if user is not None and token_generator.check_token(user, token):
            user.email_verify = True
            user.save()
            login(request, user)
            return redirect('home')
        return redirect('invalid_verify')

    @staticmethod
    def get_user(uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError,
                User.DoesNotExist, ValidationError):
            user = None
        return user


class UserLoginView(LoginView):
    form_class = AuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        user = form.user_cache

        # Обработка случая, когда требуется MFA
        if hasattr(user, 'mfa_enabled') and user.mfa_enabled:
            return render(self.request, 'registration/otp_verify.html', {
                'user_id': user.id
            })

        # Стандартная аутентификация
        login(self.request, user)
        messages.success(self.request, 'Login successful!')
        return redirect(self.get_success_url())

    def form_invalid(self, form):
        # Обработка ошибки MFA
        for error in form.errors.as_data().get('__all__', []):
            if error.code == 'mfa_required':
                return render(self.request, 'registration/otp_verify.html', {
                    'user_id': self.request.session.get('mfa_user_id')
                })
        return super().form_invalid(form)


class UserLoginViewAPI(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="User login (Django form-based)",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="User email"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="User password"),
            },
            required=['email', 'password'],
        ),
        responses={
            200: openapi.Response("Login successful!"),
            401: openapi.Response("Invalid credentials or MFA required"),
        }
    )
    def post(self, request):
        return Response({"detail": "This is a Swagger-only view. Use /user/login/ instead."})


class MfaVerify(APIView):
    @staticmethod
    def verify_2fa_otp(user, otp):
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp):
            user.mfa_enabled = True
            user.save()
            return True
        return False


    @swagger_auto_schema(
        operation_description="Verify MFA OTP code.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'otp_code': openapi.Schema(type=openapi.TYPE_STRING),
                'user_id': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['otp_code', 'user_id']
        ),
        responses={
            200: "Login success or invalid code",
            400: "Invalid request or OTP"
        }
    )
    def post(self, request):
        otp = request.POST.get('otp_code')
        user_id = request.POST.get('user_id')
        if not user_id:
            messages.error(request, 'Invalid user id. Please try again.')
            return render(request, 'registration/otp_verify.html', {'user_id': user_id})

        user = User.objects.get(id=user_id)
        if self.verify_2fa_otp(user, otp):
            if request.user.is_authenticated:
                messages.success(request, '2FA enabled successfully !')
                return redirect('mfa')

            login(request, user)
            messages.success(request, 'Login successful!')
            return redirect('mfa')
        else:
            if request.user.is_authenticated:
                messages.error(request, 'Invalid OTP code. Please try again.')
                return redirect('mfa')
            messages.error(request, 'Invalid OTP code. Please try again.')
            return render(request, 'registration/otp_verify.html', {'user_id': user_id})


class MfaDisable(LoginRequiredMixin, APIView):
    @swagger_auto_schema(
        operation_description="Disable MFA for the current user.",
        responses={302: "Redirects to profile with success or info message"}
    )
    def get(self, request):
        user = request.user
        if user.mfa_enabled:
            user.mfa_enabled = False
            user.save()
            messages.success(request, "Two-Factor Authentication has been disabled.")
            return redirect('profile')
        else:
            messages.info(request, "2FA is already disabled.")
        return redirect('profile')


class ProfileEditAPIView(APIView):
    permission_classes = [IsAuthenticated]
    template_name = 'user/profile_edit.html'

    @swagger_auto_schema(
        operation_description="Отображение формы редактирования профиля",
        responses={
            200: openapi.Response(
                description="Форма редактирования профиля",
                examples={
                    "application/html": {
                        "description": "Рендеринг шаблона profile_edit.html с формой"
                    }
                }
            )
        }
    )
    def get(self, request):
        form = ProfileForm(instance=request.user)
        return render(request, self.template_name, {'form': form})

    @swagger_auto_schema(
        operation_description="Сохранение изменений профиля",
        responses={
            302: openapi.Response(
                description="Перенаправление на просмотр профиля",
                examples={
                    "application/json": {
                        "redirect_to": "profile"
                    }
                }
            ),
            400: openapi.Response(
                description="Ошибка валидации формы",
                examples={
                    "application/html": {
                        "description": "Рендеринг шаблона с ошибками формы"
                    }
                }
            )
        }
    )
    def post(self, request):
        form = ProfileForm(request.POST, request.FILES, instance=request.user)

        if form.is_valid():
            user = form.save(commit=False)
            user.profile_complete = True
            user.save()
            messages.success(request, 'Анкета успешно сохранена!')
            return redirect('profile')

        # Логирование для отладки (можно удалить в продакшене)
        print("Form errors:", form.errors)
        print("Files received:", request.FILES)

        return render(request, self.template_name, {'form': form}, status=400)


def get_recommended_profiles(user, excluded_ids, base_filters):
    user_liked_ids = list(user.sent_likes.values_list('receiver_id', flat=True))

    users_with_common_likes = Like.objects.filter(
        receiver_id__in=user_liked_ids
    ).exclude(sender=user).values_list('sender_id', flat=True).distinct()

    candidate_ids = Like.objects.filter(
        sender_id__in=users_with_common_likes
    ).exclude(receiver_id__in=user_liked_ids).values_list('receiver_id', flat=True)

    return User.objects.filter(
        id__in=candidate_ids
    ).filter(base_filters).exclude(
        id__in=excluded_ids
    ).annotate(
        like_count=Count('received_likes')
    ).order_by('-like_count', '?')


@login_required
def get_next_profile(request):
    excluded_ids = {
        request.user.id,
        *request.user.get_viewed_profiles(),
        *request.user.get_liked_profiles(),
    }

    base_filters = Q(
        profile_complete=True,
        gender=request.user.seeking if request.user.seeking != 'A' else Q(),
        birth_date__lte=date.today() - relativedelta(years=request.user.min_age),
        birth_date__gte=date.today() - relativedelta(years=request.user.max_age + 1)
    )

    profile = get_recommended_profiles(request.user, excluded_ids, base_filters).first()

    if not profile:
        candidates = User.objects.filter(base_filters).exclude(id__in=excluded_ids).order_by('?')
        if request.user.city:
            candidates = candidates.filter(city__iexact=request.user.city)
        profile = candidates.first()

    if not profile and excluded_ids:
        cache.delete(f'viewed_{request.user.id}')
        excluded_ids = {
            request.user.id,
            *request.user.get_liked_profiles(),
        }
        profile = get_recommended_profiles(request.user, excluded_ids, base_filters).first()

        if not profile:
            candidates = User.objects.filter(base_filters).exclude(id__in=excluded_ids).order_by('?')
            if request.user.city:
                candidates = candidates.filter(city__iexact=request.user.city)
            profile = candidates.first()

    return profile


class ViewProfilesAPIView(APIView):
    permission_classes = [IsAuthenticated]  # Замена @login_required

    @swagger_auto_schema(
        operation_description="Просмотр доступных профилей",
        responses={
            200: openapi.Response(
                description="Успешное отображение профиля",
                examples={
                    "application/html": {
                        "description": "Рендеринг шаблона profiles_list.html"
                    }
                }
            ),
            302: openapi.Response(
                description="Перенаправление",
                examples={
                    "application/json": {
                        "redirect_to": ["profile_edit", "no_profiles"]
                    }
                }
            )
        }
    )
    def get(self, request):
        # Проверка заполненности профиля
        if not request.user.profile_complete:
            messages.warning(request, "Пожалуйста, заполните свой профиль полностью")
            return redirect('profile_edit')

        # Получение следующего профиля
        profile = get_next_profile(request)

        if not profile:
            return render(request, 'user/no_profiles.html')

        return render(request, 'user/profiles_list.html', {'profile': profile})


class ProcessProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Обработка действия (лайк/пропуск) для профиля",
        manual_parameters=[
            openapi.Parameter(
                name='profile_id',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_INTEGER,
                description='ID профиля для действия',
                required=True
            ),
            openapi.Parameter(
                name='action',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                description='Тип действия (like/skip)',
                enum=['like', 'skip'],
                required=True
            )
        ],
        responses={
            302: openapi.Response(
                description="Перенаправление на страницу просмотра профилей",
                examples={
                    "application/json": {
                        "detail": "Перенаправление на view_profiles"
                    }
                }
            ),
            404: openapi.Response(
                description="Профиль не найден",
                examples={
                    "application/json": {
                        "detail": "Not found"
                    }
                }
            )
        }
    )
    def post(self, request, profile_id, action):
        """Обрабатывает действие (лайк/пропуск)"""
        profile = get_object_or_404(User, id=profile_id)

        if action == 'like':
            Like.objects.get_or_create(
                sender=request.user,
                receiver=profile
            )
            messages.success(request, "Лайк отправлен!")

            # Проверяем, есть ли взаимный лайк
            if Like.objects.filter(sender=profile, receiver=request.user).exists():
                # Создаем уведомление о взаимном лайке
                MatchNotification.objects.get_or_create(
                    user=request.user,
                    matched_user=profile
                )
                MatchNotification.objects.get_or_create(
                    user=profile,
                    matched_user=request.user
                )
                messages.success(request, f"У вас взаимная симпатия с {profile.name}!")

        elif action == 'skip':
            request.user.add_viewed_profile(profile.id)

        return redirect('view_profiles')


class MfaView(APIView):
    template_name = 'user/mfa.html'

    @swagger_auto_schema(
        operation_description="Generate and return MFA QR code.",
        responses={200: 'Rendered MFA setup page with QR code.'}
    )
    def get(self, request):
        user = request.user
        if not user.mfa_secret:
            user.mfa_secret = pyotp.random_base32()
            user.save()

        otp_uri = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(
            name=user.email,
            issuer_name="Datum"
        )
        qr = qrcode.make(otp_uri)
        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")

        buffer.seek(0)
        qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")

        qr_code_data_uri = f"data:image/png;base64,{qr_code}"

        return render(request, self.template_name, {"qrcode": qr_code_data_uri})


class TapeView(APIView):
    template_name = 'user/tape.html'

    @swagger_auto_schema(
        operation_description="Render user's tape (feed).",
        responses={200: 'Rendered tape page.'}
    )
    def get(self, request):
        return render(request, self.template_name)

class FiltersEditAPIView(APIView):
    permission_classes = [IsAuthenticated]  # Аналог @login_required
    template_name = 'user/filters.html'

    @swagger_auto_schema(
        operation_description="Редактирование фильтров профиля",
        responses={
            200: "Успешное отображение формы",
            302: "Перенаправление после успешного сохранения",
            400: "Неверные данные формы"
        }
    )
    def get(self, request):
        form = ProfileForm(instance=request.user)
        return render(request, self.template_name, {'form': form})

    @swagger_auto_schema(
        operation_description="Сохранение фильтров профиля",
        responses={
            302: "Перенаправление после успешного сохранения",
            400: "Неверные данные формы"
        }
    )
    def post(self, request):
        form = ProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            user = form.save(commit=False)
            user.profile_complete = True
            user.save()
            messages.success(request, 'Анкета успешно сохранена!')
            return redirect('profile')
        else:
            messages.error(request, 'Ошибка при сохранении формы')
            return render(request, self.template_name, {'form': form}, status=status.HTTP_400_BAD_REQUEST)


def tracking_pixel(request):
    logging.info("-------TRACKING--------")
    uid = request.GET.get('uid', 'unknown')
    ip = request.META.get('REMOTE_ADDR')

    logging.info(datetime.now())
    logging.info(f"UID: {uid}")
    logging.info(f"IP: {ip}")

    # Путь к пикселю (1x1 прозрачное PNG)
    from django.http import HttpResponse

    with open("static/user/img/default_profile_pic.jpg", 'rb') as f:
        return HttpResponse(f.read(), content_type='image/jpeg')



class MatchesView(APIView):
    permission_classes = [IsAuthenticated]
    template_name = 'user/matches.html'

    @swagger_auto_schema(
        operation_description="View mutual likes (matches)",
        responses={200: 'Rendered matches page with mutual likes.'}
    )
    def get(self, request):
        # Получаем ID пользователей, которым текущий пользователь поставил лайк
        liked_users_ids = request.user.sent_likes.values_list('receiver_id', flat=True)

        # Получаем пользователей, которые также поставили лайк текущему пользователю
        mutual_likes = User.objects.filter(
            sent_likes__receiver=request.user,
            id__in=liked_users_ids
        ).distinct()

        # Помечаем уведомления как прочитанные
        MatchNotification.objects.filter(
            user=request.user,
            matched_user__in=mutual_likes
        ).update(is_read=True)

        return render(request, self.template_name, {'matches': mutual_likes})


class NotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    template_name = 'user/notifications.html'

    @swagger_auto_schema(
        operation_description="View user notifications",
        responses={200: 'Rendered notifications page.'}
    )
    def get(self, request):
        notifications = request.user.notifications.order_by('-created_at')
        return render(request, self.template_name, {'notifications': notifications})


class MessageAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        """Получить историю сообщений с пользователем"""
        other_user = get_object_or_404(User, id=user_id)

        # Помечаем сообщения как прочитанные
        Message.objects.filter(
            sender=other_user,
            receiver=request.user,
            is_read=False
        ).update(is_read=True)

        messages = Message.objects.filter(
            (Q(sender=request.user) & Q(receiver=other_user)) |
            (Q(sender=other_user) & Q(receiver=request.user))
        ).order_by('timestamp')

        return Response({
            'messages': [
                {
                    'id': msg.id,
                    'sender': msg.sender.id,
                    'content': msg.content,
                    'timestamp': timezone.localtime(msg.timestamp).strftime('%H:%M'),
                    'is_read': msg.is_read
                }
                for msg in messages
            ]
        })

    def post(self, request, user_id):
        """Отправить сообщение пользователю"""
        other_user = get_object_or_404(User, id=user_id)
        content = request.data.get('content', '').strip()

        if not content:
            return Response({'error': 'Message cannot be empty'}, status=400)

        message = Message.objects.create(
            sender=request.user,
            receiver=other_user,
            content=content
        )

        return Response({
            'status': 'success',
            'message': {
                'id': message.id,
                'content': message.content,
                'timestamp': timezone.localtime(message.timestamp).strftime("%H:%M"),
            }
        })
