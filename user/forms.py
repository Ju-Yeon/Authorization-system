from django import forms
from .models import User

class SigninForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email', 'password']

class SignupForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email', 'password']

class PasswordForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email']

class ChangeForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email', 'password']