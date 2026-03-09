from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser

class SignUpForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ("username", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # This removes the overlapping "Your password can't be too similar..." text
        self.fields['username'].help_text = ""
        self.fields['password1'].help_text = ""