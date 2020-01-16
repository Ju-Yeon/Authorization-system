from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from user.models import User
from .forms import SigninForm, SignupForm
import hashlib

from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from .tokens import account_activation_token
from django.utils.encoding import force_bytes, force_text

from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

import jwt
import time

JWT_SECRET = 'mysecretkey'

# Create your views here.
def index(request):
    if request.COOKIES.get('auth') is None:
        return render(request, 'user/index.html', {})
    else:
        auth = str(request.COOKIES.get('auth'))
        print("index_cookies: "+auth)
        return render(request, 'user/index.html', {'auth': auth})

def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            if str(request.POST["password"]) == str(request.POST["confirm_password"]):
                name = str(request.POST["name"])

                temp = str(request.POST["password"])
                password = hashlib.sha256(temp.encode()).hexdigest()

                email = str(request.POST["email"])

                user_in_db = User.objects.filter(email = email)
                if user_in_db.count() == 0:
                    user = User(name = name, password = password, email = email)
                    #user = form.save(commit = False)
                    user.is_active = False
                    user.save()

                    #이메일인증
                    current_site = get_current_site(request)
                    # localhost:8000
                    message = render_to_string('user/user_activate_email.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                        'token': account_activation_token.make_token(user),
                    })

                    mail_subject = "회원가입 인증 메일입니다."
                    user_email = email
                    email = EmailMessage(mail_subject, message, to=[user_email])
                    #email.send()
                    return HttpResponse(
                        '<div style="font-size: 40px; width: 100%; height:100%; display:flex; text-align:center; '
                        'justify-content: center; align-items: center; font-family: "Montserrat", "sans-serif";" >'
                        '입력하신 이메일<span>로 인증 링크가 전송되었습니다.</span>'
                        '</div>'
                    )
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
                temp = str(request.POST["password"])
                password = hashlib.sha256(temp.encode()).hexdigest()

                if user[0].password == password:

                    #로그인 인증 토큰 발행
                    expire_ts = int(time.time()) + 3600
                    payload = {'useremail': user[0].email, 'expire': expire_ts}
                    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256').decode()

                    messages.info(request, user[0].name + "님 환영합니다.")
                    response = redirect('/')
                    response.set_cookie('auth', token)
                    return response
                else:
                    messages.info(request, "비밀번호가 올바르지 않습니다.")
                    return redirect('signin')
            else:
                messages.info(request, "존재하지 않는 이메일 입니다.")
                return redirect('signin')
    else:
        form = SigninForm()
        return render(request, 'user/signin.html', {'form': form})

def activate(request, uid64, token):

    uid = force_text(urlsafe_base64_decode(uid64))
    user = User.objects.get(pk=uid)

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        #로그인해주는 부분
        return redirect('/')
    else:
        return HttpResponse('비정상적인 접근입니다.')

def signout(request):
    messages.info(request, "사용자 정보가 로그아웃 됩니다.")
    response = render(request, 'user/index.html')
    response.delete_cookie('auth')
    return response


