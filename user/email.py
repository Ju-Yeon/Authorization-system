from django.shortcuts import render, redirect, HttpResponse
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from .tokens import account_activation_token
from django.utils.encoding import force_bytes, force_text

def email_signup(request, user):
    current_site = get_current_site(request)

    message = render_to_string('user/user_activate_email.html', {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
        'token': account_activation_token.make_token(user),
    })

    mail_subject = "회원가입 인증 메일입니다."
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.send()
    return HttpResponse(
        '<div style="font-size: 40px; width: 100%; height:100%; display:flex; text-align:center; '
        'justify-content: center; align-items: center; font-family: "Montserrat", "sans-serif";" >'
        '입력하신 이메일<span>로 인증 링크가 전송되었습니다.</span>'
        '</div>'
    )

def email_password(request, user):
    current_site = get_current_site(request)

    message = render_to_string('user/user_password_email.html', {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
        'token': account_activation_token.make_token(user),
    })

    mail_subject = "비밀번호 인증 이메일입니다."
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.send()
    return HttpResponse(
        '<div style="font-size: 40px; width: 100%; height:100%; display:flex; text-align:center; '
        'justify-content: center; align-items: center; font-family: "Montserrat", "sans-serif";" >'
        '입력하신 이메일<span>로 비밀번호 변경 인증 링크가 전송되었습니다.</span>'
        '</div>'
    )