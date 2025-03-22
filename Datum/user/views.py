from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
# Create your views here.

def login(request):
    # if request.method == 'POST':
    #     username = request.POST['username']
    #     password = request.POST['password']
    #     user = authenticate(request, username=username, password=password)
    #     if user is not None:
    #         login(request, user)
    #         return redirect('home')  # Замените 'home' на ваш URL
    #     else:
    #         messages.error(request, 'Invalid username or password')
    return render(request, 'user/login.html')

def signup(request):
    # if request.method == 'POST':
    #     form = UserCreationForm(request.POST)
    #     if form.is_valid():
    #         form.save()
    #         username = form.cleaned_data.get('username')
    #         password = form.cleaned_data.get('password1')
    #         user = authenticate(username=username, password=password)
    #         login(request, user)
    #         return redirect('home')  # Замените 'home' на ваш URL
    # else:
    #     form = UserCreationForm()
    return render(request, 'user/registration.html')
