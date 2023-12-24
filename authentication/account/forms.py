import threading
from typing import Any
from django import forms 
from django.contrib.auth import get_user_model 

from django.contrib.auth.forms import PasswordResetForm
from django.forms.utils import ErrorList


User = get_user_model()


class LoginForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})
    
    username = forms.CharField(
        max_length=150,
    )
    
    password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput
    )
    

class UserRegistrationForm(forms.ModelForm):
    
    password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput, 
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})
        
    class Meta:
        model = User 
        fields = (
            "username",
            "email",
            "password"
        )
        
    # username validation 
    def clean_username(self):
        model = self.Meta.model
        username = self.cleaned_data.get("username")
        
        if model.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("A user with this username already exist!")
        
        return username 
    
    # username validation 
    def clean_email(self):
        model = self.Meta.model
        email = self.cleaned_data.get("email")
        
        if model.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("A user with this username already exist!")
        
        return email
    
    # for confirm password field 
    def clean_password(self, *args, **kwargs):
        password = self.cleaned_data.get('password')
        password2 = self.data.get('password2')
        
        if password != password2:
            raise forms.ValidationError("Password mismatch!")
        
        return password
        
    
    def save(self, commit=True, *args, **kwargs):
        user = self.instance 
        # hashed the password 
        user.set_password(self.cleaned_data.get('password'))
        
        if commit:
            user.save()
        
        return user 


class ChangedPasswordForm(forms.Form):
    
    current_password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput, 
    )
    
    new_password1 = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput, 
    )
    
    new_password2 = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput, 
    )
    
    def __init__(self, user, *args, **kwargs):
        self.user = user 
        super().__init__(*args, **kwargs)
    
        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})
    
    # validate current password 
    def clean_current_password(self, *args, **kwargs):
        current_password = self.cleaned_data.get('current_password')
        
        if not self.user.check_password(current_password):
            raise forms.ValidationError("Current password is wrong!")
        return current_password
            
    
    # for confirm password field 
    def clean_new_password1(self, *args, **kwargs):
        new_password1 = self.cleaned_data.get('new_password1')
        new_password2 = self.data.get('new_password2')
        
        if new_password1 != new_password2:
            raise forms.ValidationError("Password mismatch!")
        
        return new_password1


class SendEmailForm(PasswordResetForm, threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        threading.Thread.__init__(self)
    
        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})
        
    def clean_email(self, *args, **kwargs):
        if not User.objects.filter(email__iexact=self.cleaned_data.get("email")).exists():
            raise forms.ValidationError("Unregistered email. Please enter registered email!")
        return self.cleaned_data.get("email")
    
    def run(self) -> None:
        return super().send_mail(
            self.subject_template_name, 
            self.email_template_name, 
            self.context, 
            self.from_email, 
            self.to_email, 
            self.html_email_template_name
        )
        
    def send_mail(self, subject_template_name: str, email_template_name: str, context: dict[str, Any], from_email: str | None, to_email: str, html_email_template_name: str | None = ...) -> None:
        self.subject_template_name = subject_template_name
        self.email_template_name = email_template_name
        self.context = context
        self.from_email = from_email
        self.to_email = to_email
        self.html_email_template_name = html_email_template_name
        self.start()


class ResetPasswordConfirmForm(forms.Form):
    new_password1 = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput, 
    )
    
    new_password2 = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput, 
    )
    
    def __init__(self, user, *args, **kwargs):
        self.user = user 
        super().__init__(*args, **kwargs)
    
        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})   
    
    # for confirm password field 
    def clean_new_password1(self, *args, **kwargs):
        new_password1 = self.cleaned_data.get('new_password1')
        new_password2 = self.data.get('new_password2')
        
        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise forms.ValidationError("Password mismatch!")
        else:
            raise forms.ValidationError("Please enter password and confirm password both!")
        
        return new_password1

    def save(self, commit=True, *args, **kwargs):
        # set the password 
        self.user.set_password(self.cleaned_data.get('new_password1'))
        
        if commit:
            self.user.save()
        
        return self.user 
        