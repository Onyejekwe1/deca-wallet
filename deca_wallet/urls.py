"""deca_wallet_main URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
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
from django.urls import path
from .views import RegisterUser, Login, Wallets, Fund, Withdrawal, WithdrawalAwaitingApproval, Approve, Promote, Demote

urlpatterns = [
    path('register', RegisterUser.as_view(), name='register_user'),
    path('login', Login.as_view(), name='login_user'),
    path('create_wallet', Wallets.as_view(), name='add_wallet'),
    path('get_wallet', Wallets.as_view(), name='get_user_wallet'),
    path('fund_wallet', Fund.as_view(), name='fund_user_wallet'),
    path('withdraw', Withdrawal.as_view(), name='withdrawal'),
    path('awaiting_approval', WithdrawalAwaitingApproval.as_view(), name='approve_withdrawal'),
    path('approve_withdrawal', Approve.as_view(), name='approve_withdrawal'),
    path('promote_user', Promote.as_view(), name='promote_user'),
    path('demote_user', Demote.as_view(), name='demote_user'),
]
