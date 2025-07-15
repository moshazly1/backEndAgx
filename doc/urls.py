from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("me/", views.me, name="me"),
    path("forgot-password/", views.forgot_password, name="forgot-password"),
    path(
        "reset-password/",
        views.reset_password,
        name="reset-password-confirm",
    ),
    path("activate/", views.activate_account, name="activate"),
    path("resend-activation/", views.resend_activation_email, name="resend-activation"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("request-demo/", views.request_demo, name="request-demo"),
    path("contact-us/", views.contact_us, name="contact-us"),
]
