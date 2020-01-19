from user.models import User
import jwt
import time

from django.core.cache import cache

JWT_SECRET = 'mysecretkey'

def get_authorization_header(request):
    if request.COOKIES.get('auth') is None:
            return None
    else:
        auth = str(request.COOKIES.get('auth'))
    return auth


def sign(email):
    expire_ts = int(time.time()) + 3600
    payload = {'useremail': email, 'expire': expire_ts}
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256').decode()
    return token


def verify(request):
    token = get_authorization_header(request)
    if not token:
        return None

    #redis 값 검증
    if cache.get(token):
        return None

    # token 디코딩
    payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

    # token 만료 확인
    expire = payload.get('expire')
    if int(time.time()) > expire:
        return None

    # user 객체
    useremail = payload.get('useremail')
    if not useremail:
        return None

    try:
        user = User.objects.filter(email=useremail)
    except user[0].DoesNotExist:
        return None

    result = {"user":user[0], "token":token}
    return result

