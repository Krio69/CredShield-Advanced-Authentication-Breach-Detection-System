from .utils import check_password_breach
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.utils.timezone import now
from django.http import HttpResponseForbidden, HttpResponse
from datetime import timedelta, date
import random
from .models import CustomUser, SecurityAuditLog, BlacklistedIP
from .forms import SignUpForm

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def get_client_ip(request):
    """Helper function to extract user IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# ---------------------------------------------------------------------------
# Feature 2: Session Fingerprinting Middleware
# Placed here so no new file is created; registered in settings.MIDDLEWARE
# ---------------------------------------------------------------------------

class SessionFingerprintMiddleware:
    """
    Compares the User-Agent stored at login time against every subsequent
    request. If they diverge the session is forcibly terminated.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            stored_ua = request.session.get('session_user_agent')
            current_ua = request.META.get('HTTP_USER_AGENT', '')
            if stored_ua and stored_ua != current_ua:
                logout(request)
                return redirect('login')
        return self.get_response(request)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

def register_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)

            password = form.cleaned_data.get('password1')
            if password:
                leak_count = check_password_breach(password)
                if leak_count > 0:
                    request.session['security_warning'] = (
                        f"Warning: This password was found in {leak_count} public leaks!"
                    )

            return redirect('success')
    else:
        form = SignUpForm()
    return render(request, 'register.html', {'form': form})


def login_view(request):
    message = ""

    # ------------------------------------------------------------------
    # Feature 1: IP Jail check — block jailed IPs before any processing
    # ------------------------------------------------------------------
    client_ip = get_client_ip(request)
    if BlacklistedIP.objects.filter(ip_address=client_ip).exists():
        return HttpResponseForbidden(
            "<h2>403 Forbidden</h2>"
            "<p>Your IP address has been blocked due to excessive failed login attempts.</p>"
        )

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(username=username)

            if user.is_locked:
                if user.is_lock_time_expired():
                    user.unlock_account()
                else:
                    message = "Account locked. Try again later."
                    return render(request, "login.html", {"message": message})

            user_auth = authenticate(request, username=username, password=password)

            if user_auth:
                # Reset brute-force counter
                user.failed_attempts = 0
                user.save()
                login(request, user_auth)

                # --------------------------------------------------------
                # Feature 2: Session Fingerprinting — store UA at login
                # --------------------------------------------------------
                request.session['session_user_agent'] = request.META.get('HTTP_USER_AGENT', '')

                # --------------------------------------------------------
                # Feature 4: Adaptive MFA Trigger
                # If this IP has NEVER successfully logged in for this user,
                # treat it as a new/unknown IP and require MFA.
                # --------------------------------------------------------
                known_ip = SecurityAuditLog.objects.filter(
                    user=user_auth,
                    ip_address=client_ip,
                    status='SUCCESS',
                ).exists()
                if not known_ip:
                    otp = str(random.randint(100000, 999999))
                    request.session['mfa_required'] = True
                    request.session['mfa_otp'] = otp
                    request.session['mfa_user_id'] = user_auth.pk
                    # In production send via email/SMS; console backend prints it
                    print(f"[CredShield MFA] OTP for {user_auth.username}: {otp}")
                    return redirect('mfa_verify')

                # Log successful login (only for already-known IPs that skip MFA)
                SecurityAuditLog.objects.create(
                    user=user_auth,
                    username_attempted=username,
                    ip_address=client_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT', 'unknown'),
                    status='SUCCESS',
                )

                # Breach detection
                leak_count = check_password_breach(password)
                if leak_count > 0:
                    request.session['security_warning'] = (
                        f"This password was found in {leak_count} public data breaches. "
                        f"Your account is at risk!"
                    )
                else:
                    request.session.pop('security_warning', None)

                return redirect("success")

            else:
                user.failed_attempts += 1
                user.last_failed_attempt = now()

                # Log failed attempt
                SecurityAuditLog.objects.create(
                    username_attempted=username,
                    ip_address=client_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT', 'unknown'),
                    status='FAILED',
                )

                # --------------------------------------------------------
                # Feature 1: IP Jailing — jail IP after >10 total failures
                # --------------------------------------------------------
                total_ip_failures = SecurityAuditLog.objects.filter(
                    ip_address=client_ip,
                    status='FAILED',
                ).count()
                if total_ip_failures > 10:
                    BlacklistedIP.objects.get_or_create(
                        ip_address=client_ip,
                        defaults={'reason': 'Exceeded 10 failed login attempts'},
                    )
                    return HttpResponseForbidden(
                        "<h2>403 Forbidden</h2>"
                        "<p>Your IP has been permanently blocked after repeated failed attempts.</p>"
                    )

                if user.failed_attempts >= 3:
                    user.lock_account()
                    message = "Account locked due to multiple failed attempts."
                else:
                    message = f"Invalid credentials. Attempts left: {3 - user.failed_attempts}"
                user.save()

        except CustomUser.DoesNotExist:
            message = "User does not exist."

    return render(request, "login.html", {"message": message})


def mfa_verify_view(request):
    """
    Feature 4: Simple OTP verification page for new/unknown IPs.
    The OTP is printed to the console (EMAIL_BACKEND = console).
    """
    if not request.session.get('mfa_required'):
        return redirect('login')

    message = ""
    if request.method == "POST":
        entered_otp = request.POST.get("otp", "").strip()
        if entered_otp == request.session.get('mfa_otp'):
            # OTP correct — clear MFA flags and finalise the login audit log
            user_id = request.session.pop('mfa_user_id', None)
            request.session.pop('mfa_required', None)
            request.session.pop('mfa_otp', None)

            if user_id:
                try:
                    user = CustomUser.objects.get(pk=user_id)
                    SecurityAuditLog.objects.create(
                        user=user,
                        username_attempted=user.username,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', 'unknown'),
                        status='SUCCESS',
                    )
                except CustomUser.DoesNotExist:
                    pass

            return redirect('success')
        else:
            message = "Invalid OTP. Please try again."

    # Render inline HTML to avoid creating a new template file
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>MFA Verification | CredShield</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <style>body {{ background:#050505; color:white; font-family:'Inter',sans-serif; }}</style>
    </head>
    <body class="flex items-center justify-center min-h-screen">
      <div class="bg-[#111] border border-[#222] rounded-2xl p-10 w-full max-w-md">
        <h1 class="text-2xl font-bold text-blue-400 mb-2">New IP Detected</h1>
        <p class="text-gray-400 text-sm mb-6">
          We don't recognise the IP address you're logging in from.
          A one-time passcode has been printed to the server console.
          Enter it below to continue.
        </p>
        {"<p class='text-red-400 text-sm mb-4'>" + message + "</p>" if message else ""}
        <form method="post">
          <input type="hidden" name="csrfmiddlewaretoken" value="{{% csrf_token %}}">
          <input
            type="text" name="otp" maxlength="6" placeholder="6-digit OTP"
            class="w-full bg-[#1a1a1a] border border-[#333] rounded-xl px-4 py-3 text-white
                   focus:outline-none focus:border-blue-500 text-center tracking-[0.5em] text-xl mb-4"
            autofocus
          />
          <button type="submit"
            class="w-full py-3 rounded-xl bg-blue-600 hover:bg-blue-500 font-semibold transition-all">
            Verify
          </button>
        </form>
        <a href="/" class="block text-center text-gray-500 text-xs mt-6 hover:text-gray-300">
          Cancel &amp; return to login
        </a>
      </div>
    </body>
    </html>
    """
    # We need a real Django template render for CSRF — use render() with inline string via Template
    from django.template import Template, Context, RequestContext
    from django.middleware.csrf import get_token
    csrf_token = get_token(request)
    html = html.replace('{{% csrf_token %}}', csrf_token)
    return HttpResponse(html)


def success_view(request):
    """Dashboard showing personalised security logs and dynamic security score"""
    if not request.user.is_authenticated:
        return redirect('login')

    # ------------------------------------------------------------------
    # Feature 3: Security Score Decay
    # Start at 100, subtract 5 points per 30-day period since last change.
    # Fall back to account creation date if never explicitly changed.
    # ------------------------------------------------------------------
    user = request.user
    reference_date = user.last_password_change or user.date_joined.date()
    days_elapsed = (date.today() - reference_date).days
    decay_periods = days_elapsed // 30          # full 30-day blocks
    security_score = max(0, 100 - (decay_periods * 5))

    logs = SecurityAuditLog.objects.filter(user=user)[:5]
    return render(request, 'success.html', {
        'logs': logs,
        'security_score': security_score,
    })


def change_password(request):
    """Handles functional password updates"""
    if not request.user.is_authenticated:
        return redirect('login')
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            # Feature 3: reset the decay clock
            user.last_password_change = date.today()
            user.save(update_fields=['last_password_change'])
            request.session.pop('security_warning', None)
            return redirect('success')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_password.html', {'form': form})
