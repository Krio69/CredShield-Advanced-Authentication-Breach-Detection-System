from django.contrib import admin
from .models import CustomUser, SecurityAuditLog, BlacklistedIP

# Register your CustomUser model
@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'failed_attempts', 'is_staff')
    search_fields = ('username', 'email')

# Register your SecurityAuditLog model
@admin.register(SecurityAuditLog)
class SecurityAuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'ip_address', 'status', 'timestamp')
    list_filter = ('status', 'timestamp')

# Feature: IP Jailing — admin interface for managing blocked IPs
@admin.register(BlacklistedIP)
class BlacklistedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'created_at')
    search_fields = ('ip_address',)
    list_filter = ('created_at',)
