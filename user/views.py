from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from user.models import User
from .forms import SigninForm, SignupForm, PasswordForm, ChangeForm
import hashlib
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from .tokens import account_activation_token
from django.utils.encoding import force_bytes, force_text
from .email import email_signup, email_password
from .jwt import verify,sign
from django.core.cache import cache



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
                email = str(request.POST["email"])
                user_in_db = User.objects.filter(email = email)
                if user_in_db.count() == 0:
                    user = form.save()
                    user.encrypt_password();
                    user.is_active = False
                    user.save()

                    return email_signup(request, user)
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

                #비밀번호 체크
                temp = str(user[0].id) + str(request.POST["password"])
                password = hashlib.sha256(temp.encode()).hexdigest()
                if user[0].password == password:

                    #로그인시 토큰 발행 및 캐시작업
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

        #로그인 토큰발행 및 캐시작업
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

                return email_password(request, user[0])
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
        if form.is_valid():
            if str(request.POST["confirm_password"]) == str(request.POST["password"]):
                    user = User.objects.filter(email = str(request.POST["email"]))
                    if user.count() == 1:

                        #변경 비밀번호 암호화 저장
                        temp = str(user[0].id) + str(request.POST["password"])
                        user[0].password = hashlib.sha256(temp.encode()).hexdigest()
                        user[0].save()

                        messages.info(request, "비밀번호가 변경되었습니다.")
                        return redirect('index')
                    else:
                        messages.info(request, "해당하는 이메일이 존재하지 않습니다.")
                        return render(request, 'user/changePassword.html', {'form': form})
            else:
                messages.info(request, "비밀번호 확인이 올바르지 않습니다.")
                return render(request,'user/changePassword.html',{'form':form})
        else:
            messages.info(request, "입력이 올바르지 않습니다.")
            return render(request,'user/changePassword.html',{'form':form})

    else:
        uid = force_text(urlsafe_base64_decode(uid64))
        user = User.objects.get(pk=uid)

        if user is not None and account_activation_token.check_token(user, token):
            form = ChangeForm()
            return render(request, 'user/changePassword.html', {'form': form, 'email': user.email})
        else:
            return HttpResponse('비정상적인 접근입니다.')


def admin(request):
    result = verify(request)

    if result is None:
        print("user is not exist or token was not valuable")
        return render(request, 'user/index.html', {})
    else:
        users = User.objects.exclude(name='admin')
        return render(request, 'user/admin.html', {'user': result["user"], 'users': users})


def delete(request,id):
    user = User.objects.get(id=id)
    user.delete()
    messages.info(request, "선택하신 계정이 삭제되었습니다.")
    return redirect('admin')
