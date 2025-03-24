import io
import base64
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from django.views import View
from .forms import UserCreationForm, AuthenticationForm
from django.shortcuts import redirect
from .utils import send_email_for_verify
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.contrib import messages
from django.urls import reverse_lazy
import pyotp
import qrcode
from django.contrib.auth.mixins import LoginRequiredMixin
# Create your views here.

User = get_user_model()

class ProfileView(LoginRequiredMixin, View):
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
class SignUpView(View):
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

class EmailVerify(View):

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

class MfaVerify(View):

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
                return redirect('profile')

            login(request, user)
            messages.success(request, 'Login successful!')
            return redirect('profile')
        else:
            if request.user.is_authenticated:
                messages.error(request, 'Invalid OTP code. Please try again.')
                return redirect('profile')
            messages.error(request, 'Invalid OTP code. Please try again.')
            return render(request, 'registration/otp_verify.html', {'user_id': user_id})

class MfaDisable(LoginRequiredMixin, View):

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