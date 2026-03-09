from django.urls import path
from .views import login_view, success_view, register_view, change_password, mfa_verify_view
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('success/', success_view, name='success'),
    path('change-password/', change_password, name='change_password'),
    # Feature 4: Adaptive MFA — OTP verification for unknown IPs
    path('mfa/verify/', mfa_verify_view, name='mfa_verify'),
]