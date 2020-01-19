from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('signup/', views.signup, name='signup'),
    path('signin/', views.signin, name='signin'),
    path('signout/',views.signout, name='signout'),
    path('password/',views.password, name = 'password'),
    path('activate/<str:uid64>/<str:token>/', views.activate, name='activate'),
    path('change/<str:uid64>/<str:token>/', views.change, name='change'),
    path('change/',views.change, name='change'),
    path('admin/',views.admin, name='admin'),
    path('delete/<int:id>',views.delete, name='delete'),

    ]