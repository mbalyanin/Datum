from django.shortcuts import render
from django.contrib.auth import decorators
from .forms import SignUpForm
from django.views.generic.edit import FormView
# Create your views here.

@decorators.login_required
def home(request):
    return render(request, 'user/home.html')

class SignUpView(FormView):
    form_class = SignUpForm
    template_name = 'registration/signup.html'
    success_url = '/user'

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)
