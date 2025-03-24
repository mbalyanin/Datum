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
import pyotp
# Create your views here.

User = get_user_model()
def home(request):
    return render(request, 'user/home.html')

class SignUpView(View):
    template_name = 'registration/signup.html'

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
            return redirect('confirm_email')
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


class MfaVerify(View):

    def verify_2fa_otp(self, user, otp):
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
            return render(request, 'otp_verify.html', {'user_id': user_id})

        user = User.objects.get(id=user_id)
        if verify_2fa_otp(user, otp):
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
            return render(request, 'otp_verify.html', {'user_id': user_id})

    return render(request, 'otp_verify.html', {'user_id': user_id})