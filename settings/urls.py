"""settings URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from fyp.views import * 

def default_redirect(request):
    return redirect('/')

urlpatterns = [
    path('login/', LoginView, name='login'),
    path('admin/', admin.site.urls),
    path('index/', IndexView, name='index'),
    path('register/', RegisterView, name='register'),
    path('success/', SuccessView, name="success"),
    path('logout/', LogoutView, name="logout"),
    path('mfa/', MFAView, name="mfa"),
    path('verify_mfa/', verify_mfa, name="verify_mfa"),
    path('password/create/', CreateView, name='createpw'),
    path('password/delete/', DeleteView, name='deletepw'),
    path('password/modify/', ModifyView, name='modifypw')
]
