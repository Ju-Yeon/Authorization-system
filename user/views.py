from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from user.models import User
from .forms import SigninForm, SignupForm, PasswordForm, ChangeForm
import hashlib


from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from .tokens import account_activation_token
from django.utils.encoding import force_bytes, force_text

from .jwt import verify,sign

from django.core.cache import cache

from django.urls import resolve


# Create your views here.
def index(request):
    result = verify(request)
    if result is None:
        print("user is not exist or token was not valuable")
        return render(request, 'user/index.html', {})
    else:
        return render(request, 'user/index.html', {'user': result["user"]})


def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            if str(request.POST["password"]) == str(request.POST["confirm_password"]):
                name = str(request.POST["name"])
                password = str(request.POST["password"])
                email = str(request.POST["email"])

                user_in_db = User.objects.filter(email = email)
                if user_in_db.count() == 0:
                    user = User(name = name, password = "", email = email)
                    #user = form.save(commit = False)
                    user.is_active = False
                    user.save()

                    #비밀번호암호화
                    user_in_db = User.objects.get(email = email)
                    temp = str(user_in_db.id) + password;
                    user_in_db.password = hashlib.sha256(temp.encode()).hexdigest()
                    user_in_db.save()

                    #이메일인증
                    current_site = get_current_site(request)

                    message = render_to_string('user/user_activate_email.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                        'token': account_activation_token.make_token(user),
                    })

                    mail_subject = "회원가입 인증 메일입니다."
                    user_email = email
                    email = EmailMessage(mail_subject, message, to=[user_email])
                    email.send()
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
                return redirect('/signup')
    else:
        form = SignupForm()
        return render(request, 'user/signup.html', {'form': form})


def signin(request):
    if request.method == "POST":
        form = SigninForm(request.POST)
        if form.is_valid():
            user = User.objects.filter(email=str(request.POST["email"]))
            if user.count() == 1 and user[0].is_active == 1:

                temp = str(user[0].id) + request.POST["password"]
                password = hashlib.sha256(temp.encode()).hexdigest()

                if user[0].password == password:

                    #로그인시 토큰 발행
                    token = sign(user[0].email)
                    cache.set(token, user[0].id, 60 * 60)

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


def activate(request, uid64, token, response=None):

    uid = force_text(urlsafe_base64_decode(uid64))
    user = User.objects.get(pk=uid)

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True

        #로그인 토큰발행
        token = sign(user.email)
        cache.set(token, user.id, 60 * 60)
        user.save()

        messages.info(request, user.name + "님 환영합니다.")
        response = redirect('/')
        response.set_cookie('auth', token)
        return response
    else:
        return HttpResponse('비정상적인 접근입니다.')


def signout(request):
    messages.info(request, "사용자 정보가 로그아웃 됩니다.")

    response = redirect('/')
    response.delete_cookie('auth')
    return response

def password(request):
    if request.method == "POST":
        form = PasswordForm(request.POST)

        if form.is_valid():
            user = User.objects.filter(email=str(request.POST["email"]))

            if user.count() == 1 and str(user[0].name) == str(request.POST["name"]):

                # 이메일인증
                current_site = get_current_site(request)
                message = render_to_string('user/user_password_email.html', {
                    'user': user[0],
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user[0].pk)).decode(),
                    'token': account_activation_token.make_token(user[0]),
                })

                mail_subject = "비밀번호 인증 이메일입니다."
                user_email = user[0].email
                email = EmailMessage(mail_subject, message, to=[user_email])
                email.send()
                return HttpResponse(
                    '<div style="font-size: 40px; width: 100%; height:100%; display:flex; text-align:center; '
                    'justify-content: center; align-items: center; font-family: "Montserrat", "sans-serif";" >'
                    '입력하신 이메일<span>로 비밀번호 변경 인증 링크가 전송되었습니다.</span>'
                    '</div>'
                )
                return redirect('/')

            else:
                messages.info(request, "해당하는 이메일과 이름이 존재하지 않습니다.")
                return render(request, 'user/lostPassword.html')

        else:
            messages.info(request, "입력이 올바르지 않습니다다.")
            return render(request, 'user/lostPassword.html')

    else:
        form = PasswordForm()
        return render(request, 'user/lostPassword.html', {'form': form})


def change(request, uid64=None, token=None, response=None):
    if request.method == "POST":
        form = ChangeForm(request.POST)
        email = str(request.POST["email"])
        if form.is_valid():
            if str(request.POST["confirm_password"]) == str(request.POST["password"]):
                    user = User.objects.filter(email=str(request.POST["email"]))
                    if user.count() == 1:
                        password = str(request.POST["password"])
                        temp = str(user[0].id) + password
                        user[0].password = hashlib.sha256(temp.encode()).hexdigest()
                        user[0].save()
                        messages.info(request, "비밀번호가 변경되었습니다.")
                        return redirect('index')
                    else:
                        messages.info(request, "해당하는 이메일이 존재하지 않습니다.")
                        return render(request, 'user/changePassword.html', {'form': form, 'email': email})
            else:
                messages.info(request, "비밀번호 확인이 올바르지 않습니다.")
                return render(request,'user/changePassword.html',{'form':form, 'email':email})
        else:
            messages.info(request, "입력이 올바르지 않습니다.")
            return render(request,'user/changePassword.html',{'form':form, 'email':email})

    else:
        uid = force_text(urlsafe_base64_decode(uid64))
        user = User.objects.get(pk=uid)

        if user is not None and account_activation_token.check_token(user, token):
            form = ChangeForm()
            return render(request, 'user/changePassword.html', {'form': form, 'email': user.email})
        else:
            return HttpResponse('비정상적인 접근입니다.')


def admin(request):
    users = User.objects.exclude(name='admin')
    return render(request, 'user/admin.html',{'users':users})

def delete(request,id):
    user = User.objects.get(id=id)
    user.delete()
    messages.info(request, "선택하신 계정이 삭제되었습니다.")
    return redirect('admin')
