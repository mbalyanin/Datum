from django.shortcuts import redirect
from django.urls import reverse

class ProfileCompletionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        URLS = [
            reverse('profile'),
        ]

        if (
            request.user.is_authenticated
            and not request.user.profile_complete
            and request.path in URLS
        ):
            return redirect('profile_edit')  # Перенаправляем на заполнение анкеты

        return self.get_response(request)