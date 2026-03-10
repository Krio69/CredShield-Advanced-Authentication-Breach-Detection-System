from .utils import check_password_breach
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.utils.timezone import now
from django.http import HttpResponseForbidden, HttpResponse
from django.template import Template, RequestContext
from datetime import timedelta, date
import random
from .models import CustomUser, SecurityAuditLog, BlacklistedIP
from .forms import SignUpForm

# ---------------------------------------------------------------------------
# Helpers & Middleware
# ---------------------------------------------------------------------------

def get_client_ip(request):
    """Extracts the real user IP, handling proxy headers (like Vercel/Cloudflare)"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class SessionFingerprintMiddleware:
    """Terminates session if the User-Agent changes mid-session"""
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
            
            # Check for initial password breaches
            password = form.cleaned_data.get('password1')
            if password:
                leak_count = check_password_breach(password)
                if leak_count > 0:
                    request.session['security_warning'] = f"Warning: This password was found in {leak_count} public leaks!"
            
            return redirect('success')
    else:
        form = SignUpForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    message = ""
    client_ip = get_client_ip(request)
    
    # Feature 1: IP Jailing check
    if BlacklistedIP.objects.filter(ip_address=client_ip).exists():
        return HttpResponseForbidden("<h2>403 Forbidden</h2><p>Your IP is blocked due to security violations.</p>")

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        
        try:
            user = CustomUser.objects.get(username=username)
            
            if user.is_locked:
                if user.is_lock_time_expired():
                    user.unlock_account()
                else:
                    return render(request, "login.html", {"message": "Account locked. Try again later."})

            user_auth = authenticate(request, username=username, password=password)
            
            if user_auth:
                # Check if this is a known IP for this specific user
                known_ip = SecurityAuditLog.objects.filter(
                    user=user_auth, ip_address=client_ip, status='SUCCESS'
                ).exists()
                
                if not known_ip:
                    # Trigger MFA for unknown IP
                    otp = str(random.randint(100000, 999999))
                    request.session['mfa_required'] = True
                    request.session['mfa_otp'] = otp
                    request.session['mfa_user_id'] = user_auth.pk
                    # Store backend to allow manual login later
                    request.session['mfa_user_backend'] = user_auth.backend
                    
                    print(f"[CredShield MFA] OTP for {user_auth.username}: {otp}")
                    return redirect('mfa_verify')

                # Standard Login for known IPs
                user.failed_attempts = 0
                user.save()
                login(request, user_auth)
                request.session['session_user_agent'] = request.META.get('HTTP_USER_AGENT', '')
                
                # Check for breaches on successful login
                leak_count = check_password_breach(password)
                if leak_count > 0:
                    request.session['security_warning'] = f"Warning: Password found in {leak_count} breaches!"
                
                return redirect("success")
            else:
                user.failed_attempts += 1
                user.save()
                
                # Jailing logic
                total_ip_failures = SecurityAuditLog.objects.filter(ip_address=client_ip, status='FAILED').count()
                if total_ip_failures > 10:
                    BlacklistedIP.objects.get_or_create(ip_address=client_ip, defaults={'reason': 'Brute force attempt'})
                
                return render(request, "login.html", {"message": "Invalid credentials."})
                
        except CustomUser.DoesNotExist:
            message = "User does not exist."

    return render(request, "login.html", {"message": message})

def mfa_verify_view(request):
    """Verifies OTP and completes the login process for new devices/IPs"""
    if not request.session.get('mfa_required'):
        return redirect('login')

    current_otp = request.session.get('mfa_otp')
    user_id = request.session.get('mfa_user_id')
    backend = request.session.get('mfa_user_backend')

    message = ""
    if request.method == "POST":
        entered_otp = request.POST.get("otp", "").strip()
        if entered_otp == current_otp:
            try:
                user = CustomUser.objects.get(pk=user_id)
                user.backend = backend
                
                # Complete the login
                login(request, user)
                request.session['session_user_agent'] = request.META.get('HTTP_USER_AGENT', '')
                
                # Log the successful connection from this new IP
                SecurityAuditLog.objects.create(
                    user=user,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', 'unknown'),
                    status='SUCCESS'
                )

                # Cleanup session
                for key in ['mfa_required', 'mfa_otp', 'mfa_user_id', 'mfa_user_backend']:
                    request.session.pop(key, None)
                
                return redirect('success')
            except CustomUser.DoesNotExist:
                return redirect('login')
        else:
            message = "Invalid OTP. Please check the server console."

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>MFA Verification | CredShield</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <style>body { background:#050505; color:white; font-family:'Inter',sans-serif; }</style>
    </head>
    <body class="flex items-center justify-center min-h-screen">
      <div class="bg-[#111] border border-[#222] rounded-2xl p-10 w-full max-w-md">
        <h1 class="text-2xl font-bold text-blue-400 mb-2">New IP Detected</h1>
        <p class="text-gray-400 text-sm mb-6">Enter the 6-digit code sent to your server console.</p>
        {% if message %}<p class='text-red-400 text-sm mb-4'>{{ message }}</p>{% endif %}
        <form method="post">
          {% csrf_token %}
          <input type="text" name="otp" maxlength="6" class="w-full bg-[#1a1a1a] border border-[#333] rounded-xl px-4 py-3 text-white text-center text-xl mb-4" autofocus />
          <button type="submit" class="w-full py-3 rounded-xl bg-blue-600 hover:bg-blue-500 font-semibold transition-all">Verify & Login</button>
        </form>
      </div>
    </body>
    </html>
    """
    t = Template(html_template)
    c = RequestContext(request, {'message': message})
    return HttpResponse(t.render(c))

def success_view(request):
    """Calculates security score based on password age and displays audit logs"""
    if not request.user.is_authenticated:
        return redirect('login')

    user = request.user
    # Feature 3: Security Score Decay (Logic: 100 - 5 points for every 30 days)
    reference_date = user.last_password_change or user.date_joined.date()
    days_elapsed = (date.today() - reference_date).days
    security_score = max(0, 100 - ((days_elapsed // 30) * 5))

    logs = SecurityAuditLog.objects.filter(user=user).order_by('-timestamp')[:5]
    return render(request, 'success.html', {
        'logs': logs,
        'security_score': security_score,
    })

def change_password(request):
    """Updates password and resets the security score decay clock"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            
            # Reset the decay clock
            user.last_password_change = date.today()
            user.save(update_fields=['last_password_change'])
            
            request.session.pop('security_warning', None)
            return redirect('success')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_password.html', {'form': form})