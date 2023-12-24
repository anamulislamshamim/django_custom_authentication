from django.urls import path 
from .views import (
    Home,
    Login,
    Logout,
    Registration,
    ChangePassword,
    SendEmailToResetPassword,
    ResetPasswordConfirm,
)

from django.contrib.auth.views import (
    PasswordResetDoneView,
)


# app_name = "account"


urlpatterns = [
     path('', Home.as_view(), name='home'),
     path('login/', Login.as_view(), name='login'),
     path('logout/', Logout.as_view(), name='logout'),
     path('registration/', Registration.as_view(), name="registration"),
     path('change_password', ChangePassword.as_view(), name="change_password"),
     path('password_reset/', SendEmailToResetPassword.as_view(), name="password_reset"),
     path('password_reset/done/', PasswordResetDoneView.as_view(template_name="account/password_reset_done.html"), name="password_reset_done"),
     path('reset/<uidb64>/<token>/', ResetPasswordConfirm.as_view(), name="password_reset_confirm"),
]

# https://docs.djangoproject.com/en/5.0/topics/auth/default/#using-the-views
# accounts/password_reset/ [name='password_reset']
# accounts/password_reset/done/ [name='password_reset_done']
# accounts/reset/<uidb64>/<token>/ [name='password_reset_confirm']
# accounts/reset/done/ [name='password_reset_complete']
