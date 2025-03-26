from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django import forms
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from .utils import send_email_for_verify

User = get_user_model()

class AuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'].widget.attrs.update({
            'placeholder': "Введите ваш email",
            'type': "text",
            'id': "username",
            'name': "username"
        })

        self.fields['password'].widget.attrs.update({
            'placeholder': "Give me your password",
            'type': "password",
            'id': "password",
            'name': "password"
        })
    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username is not None and password:
            self.user_cache = authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                raise self.get_invalid_login_error()
            if not self.user_cache.email_verify:
                send_email_for_verify(self.request, self.user_cache)
                raise ValidationError(
                    'Email not verify! Check your email!',
                    code='invalid_login',
                )

            if hasattr(self.user_cache, 'mfa_enabled') and self.user_cache.mfa_enabled:
                # Сохраняем частично аутентифицированного пользователя в сессии
                self.request.session['mfa_user_id'] = self.user_cache.id
                self.request.session['mfa_backend'] = self.user_cache.backend
                raise ValidationError(
                    'MFA verification required',
                    code='mfa_required',
                )
            self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data

class UserCreationForm(UserCreationForm):
    email = forms.EmailField(
        label=_("Email"),
        max_length=254,
        widget=forms.EmailInput(attrs={
            "autocomplete": "email",
            "placeholder": _("Введите ваш email"),
        }),
    )
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('email', 'password1', 'password2')
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['email'].widget.attrs.update({
            'placeholder': "Введите ваш email",
            'id': "username",
            'name': "username",
            'type': "text",
        })

        self.fields['password1'].widget.attrs.update({
            'placeholder': "Придумайте пароль",
            'id': "password1",
            'name': "password",
            'type': "password",
        })

        self.fields['password2'].widget.attrs.update({
            'placeholder': "Повторите пароль",
            'id': "password2",
            'name': "password",
            'type': "password",
        })