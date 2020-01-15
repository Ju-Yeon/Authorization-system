from django.shortcuts import render, redirect
from django.contrib import messages
from user.models import User
from .forms import SigninForm, SignupForm
import hashlib

# Create your views here.
def index(request):
    return render(request, 'user/index.html', {})

def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            if request.POST.get("password"," ") == request.POST.get("confirm_password"," "):
                name = request.POST.get("name"," ")

                str = request.POST.get("password"," ")
                password = hashlib.sha256(str.encode()).hexdigest()

                email = request.POST.get("email"," ")

                user_in_db = User.objects.filter(email = email)
                if user_in_db.count() == 0:
                    user = User(name = name, password = password, email = email)
                    user.is_active = False
                    user.save()
                    messages.info(request, name + "님 환영합니다.")
                    return redirect('/')
                else:
                    messages.info(request, "동일한 이메일이 존재합니다.")
                    return redirect('/signup')
            else:
                messages.info(request, "비밀번호 확인이 올바르지 않습니다.")
    else:
        form = SignupForm()
        return render(request, 'user/signup.html', {'form': form})

def signin(request):
    if request.method == "POST":
        form = SigninForm(request.POST)
        if form.is_valid():
            user = User.objects.filter(email=str(request.POST["email"]))
            if user:
                str = str(request.POST["password"])
                password = hashlib.sha256(str.encode()).hexdigest()

                if user[0].password == password:
                    messages.info(request, user[0].name + "님 환영합니다.")
                    return redirect('/')
                else:
                    messages.info(request, "비밀번호가 올바르지 않습니다.")
                    return redirect('signin')
            else:
                messages.info(request, "존재하지 않는 이메일 입니다.")
                return redirect('signin')
    else:
        form = SigninForm()
        return render(request, 'user/signin.html', {'form': form})

