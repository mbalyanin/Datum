from django.urls import path, include
from .views import *
from django.views.generic import TemplateView

urlpatterns = [
    path('login/', UserLoginView.as_view(), name='login'),
    path('', include('django.contrib.auth.urls')),
    path('invalid_verify/', TemplateView.as_view(template_name='registration/invalid_verify.html'), name='invalid_verify'),
    path('verify_email/<uidb64>/<token>/', EmailVerify.as_view(), name='verify_email'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('profile/edit/', ProfileEditAPIView.as_view(), name='profile_edit'),
    path('profile/view/', ViewProfilesAPIView.as_view(), name='view_profiles'),
    path('profile/<int:profile_id>/<str:action>/',
         ProcessProfileAPIView.as_view(),
         name='process_profile'),
    path('verify_mfa/', MfaVerify.as_view(), name='verify_mfa'),
    path('disable_2fa/', MfaDisable.as_view(), name='disable_2fa'),

    path('settings/', ProfileView.as_view(), name='settings'),
    path('mfa/', MfaView.as_view(), name='mfa'),
    path('tape/', TapeView.as_view(), name='tape'),
    path('filters/', FiltersEditAPIView.as_view(), name='filters'),

    path('track/', tracking_pixel, name='tracking_pixel'),
]
