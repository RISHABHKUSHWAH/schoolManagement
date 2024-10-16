from django.urls import path
from . import views

urlpatterns = [
    path('signup/',views.signup,name="signUp"),
    path('logIn/',views.logIn,name="logIn"),
    path('logout/',views.user_logout,name='logout'),
]
