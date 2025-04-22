import io
import base64
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
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

from .models import Like
# Create your views here.


User = get_user_model()

class ProfileView(LoginRequiredMixin, APIView):
    template_name = 'user/profile.html'
    login_url = '/user/login/'
    redirect_field_name = 'next'
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

    def get(self, request):
        context = {
            'form': UserCreationForm()
        }
        return render(request, self.template_name, context)

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


@login_required
def profile_edit(request):
    if request.method == 'POST':
        print("akakak")
        form = ProfileForm(request.POST, request.FILES, instance=request.user)
        print(request.FILES)
        print("edit ok")
        if form.is_valid():
            print("edit if")
            user = form.save(commit=False)
            user.profile_complete = True
            user.save()
            messages.success(request, 'Анкета успешно сохранена!')
            return redirect('profile')  # Перенаправление на просмотр анкеты
    else:
        form = ProfileForm(instance=request.user)

    return render(request, 'user/profile_edit.html', {'form': form})


@login_required
def get_next_profile(request):
    # Исключаем свою анкету и обработанные профили
    excluded_ids = {
        request.user.id,  # Своя анкета
        *request.user.get_viewed_profiles(),  # Пропущенные
        *request.user.get_liked_profiles()  # Лайкнутые
    }

    # 2. Алгоритм рекомендаций
    profile = None

    # Вариант A: из пула взаимных связей
    likers = User.objects.filter(
        sent_likes__receiver=request.user
    ).values_list('id', flat=True)

    if likers:
        profile = (
            User.objects.filter(
                received_likes__sender__in=likers,
                profile_complete=True
            )
            .exclude(id__in=excluded_ids)
            .annotate(mutual_score=Count('received_likes'))
            .order_by('-mutual_score', '?')
            .first()
        )

    # Вариант B: случайные анкеты
    if not profile:
        candidates = (
            User.objects.filter(
                profile_complete=True,
                gender=request.user.seeking,
                birth_date__lte=date.today() - relativedelta(years=request.user.min_age),
                birth_date__gte=date.today() - relativedelta(years=request.user.max_age)
            )
            .exclude(id__in=excluded_ids)
            .order_by('?')
        )

        # Можно добавить дополнительные фильтры (город и т.д.)
        if request.user.city:
            candidates = candidates.filter(city__iexact=request.user.city)

        profile = candidates.first()

    # 3. Если совсем нет анкет - сбрасываем историю (кроме лайков)
    if not profile and excluded_ids:
        cache.delete(f'viewed_{request.user.id}')
        new_excluded_ids = {
            request.user.id,
            *request.user.get_liked_profiles()  # Лайки остаются
        }
        profile = (
            User.objects.filter(profile_complete=True)
            .exclude(id__in=new_excluded_ids)
            .order_by('?')
            .first()
        )

    return profile
@login_required
def view_profiles(request):
    profile = get_next_profile(request)

    if not profile:
        return render(request, 'user/no_profiles.html')

    return render(request, 'user/profiles_list.html', {'profile': profile})


@login_required
@require_POST
def process_profile(request, profile_id, action):
    """Обрабатывает действие (лайк/пропуск)"""
    profile = get_object_or_404(User, id=profile_id)

    if action == 'like':
        Like.objects.get_or_create(
            sender=request.user,
            receiver=profile
        )
        messages.success(request, "Лайк отправлен!")
    elif action == 'skip':
        request.user.add_viewed_profile(profile.id)

    return redirect('view_profiles')
@login_required
@require_POST
def like_profile(request, profile_id):
    profile = get_object_or_404(User, id=profile_id)

    # Создаем лайк
    Like.objects.get_or_create(
        sender=request.user,
        receiver=profile
    )

    # Проверяем на взаимный лайк (мэтч)
    if Like.objects.filter(sender=profile, receiver=request.user).exists():
        messages.success(request, f"Это взаимный лайк! Вы понравились {profile.name}")

    return redirect('view_profiles')
@login_required
@require_POST
def skip_profile(request, profile_id):
    # Просто перенаправляем на следующую анкету
    return redirect('view_profiles')







class MfaView(APIView):
    template_name = 'user/mfa.html'
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
    def get(self, request):
        return render(request, self.template_name)

@login_required
def filters_edit(request):
    template_name = 'user/filters.html'
    if request.method == 'POST':
        print(request.FILES)
        form = ProfileForm(request.POST, request.FILES, instance=request.user)
        print("filters ok")
        if form.is_valid():
            print("filters if")
            user = form.save(commit=False)
            user.profile_complete = True
            user.save()
            messages.success(request, 'Анкета успешно сохранена!')
            return redirect('profile')  # Перенаправление на просмотр анкеты
        else:
            messages.success(request, 'asdasdadsasdasdasdsad')
    else:
        form = ProfileForm(instance=request.user)

    return render(request, template_name, {'form': form})
