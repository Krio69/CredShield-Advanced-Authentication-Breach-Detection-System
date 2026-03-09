from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.timezone import now
from datetime import timedelta

class CustomUser(AbstractUser):
    failed_attempts = models.IntegerField(default=0)
    is_locked = models.BooleanField(default=False)
    last_failed_attempt = models.DateTimeField(null=True, blank=True)
    # Feature: Security Score Decay — tracks when the password was last changed
    last_password_change = models.DateField(null=True, blank=True)

    def lock_account(self):
        self.is_locked = True
        self.save()

    def unlock_account(self):
        self.failed_attempts = 0
        self.is_locked = False
        self.save()

    def is_lock_time_expired(self):
        if self.last_failed_attempt:
            return now() > self.last_failed_attempt + timedelta(minutes=5)
        return False

class SecurityAuditLog(models.Model):
    # Null=True allowed for failed attempts where user isn't identified yet
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)
    username_attempted = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    status = models.CharField(max_length=20) # 'SUCCESS' or 'FAILED'
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']


# Feature: IP Jailing — stores IPs that triggered excessive failed login attempts
class BlacklistedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, default='Excessive failed login attempts')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address

    class Meta:
        verbose_name = 'Blacklisted IP'
        verbose_name_plural = 'Blacklisted IPs'
        ordering = ['-created_at']