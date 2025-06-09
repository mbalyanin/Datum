from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django import forms
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from .utils import send_email_for_verify
from datetime import date

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


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            'avatar', 'name', 'gender', 'birth_date', 'city',
            'seeking', 'min_age', 'max_age', 'bio', 'hobbies'
        ]
        widgets = {
            'birth_date': forms.DateInput(
                format='%Y-%m-%d',
                attrs={
                    'type': 'date',
                    'class': 'form-control',
                    'autocomplete': 'off'
                }
            ),
            'bio': forms.Textarea(attrs={'rows': 5}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['birth_date'].widget.attrs['id'] = f'birth_date_{id(self)}'

    def validate_required_fields(self, cleaned_data):
        errors = {}
        name = cleaned_data.get('name')
        birth_date = cleaned_data.get('birth_date')

        if not name:
            errors['name'] = "Имя является обязательным полем"
        if not birth_date:
            errors['birth_date'] = "Дата рождения является обязательным полем"

        if birth_date:
            today = date.today()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            if age < 18:
                errors['birth_date'] = "Вам должно быть не менее 18 лет"

        if errors:
            raise forms.ValidationError(errors)

    def clean(self):
        cleaned_data = super().clean()

        # Проверяем обязательные поля
        self.validate_required_fields(cleaned_data)

        # Дополнительные проверки
        min_age = cleaned_data.get('min_age')
        max_age = cleaned_data.get('max_age')
        if min_age and max_age and min_age > max_age:
            raise forms.ValidationError({
                'min_age': "Минимальный возраст не может быть больше максимального",
                'max_age': "Максимальный возраст не может быть меньше минимального"
            })

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)

        try:
            # Проверяем обязательные поля перед сохранением
            self.validate_required_fields(self.cleaned_data)
            user.profile_complete = True
        except forms.ValidationError:
            user.profile_complete = False

        if commit:
            user.save()
        return user