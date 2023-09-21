from django.shortcuts import render, HttpResponseRedirect
from .forms import signupForm, EditUserProfileForm, EditAdminProfileForm
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, SetPasswordForm, UserChangeForm
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User
# Create your views here.

def sign_up(request):
    if request.method == "POST":
        fm = signupForm(request.POST)
        if fm.is_valid():
            messages.success(request,"Account Created successfully!")
            fm.save()
            return HttpResponseRedirect('/login/')
    else:
        fm = signupForm()
    return render(request,"webapp/signup.html", {'form':fm})

def user_login(request):
    if not request.user.is_authenticated:
        if request.method == "POST":
            fm = AuthenticationForm(request=request, data=request.POST)
            if fm.is_valid():
                uname = fm.cleaned_data['username']
                upass = fm.cleaned_data['password']
                user = authenticate(username=uname, password = upass)
                if user is not None:
                    login(request, user)
                    messages.success(request,"Logged in successfully !!..")
                    return HttpResponseRedirect('/profile/')
        else:
            fm = AuthenticationForm()
        return render(request,"webapp/signin.html", {"form":fm})
    else:
        return HttpResponseRedirect('/profile/')      


def user_profile(request):
    if request.user.is_authenticated:
        print("User Authenticatd")
        if request.method == "POST":
            if request.user.is_superuser == True:
                fm = EditAdminProfileForm(request.POST, instance=request.user)
                users=User.objects.all()
            else:
                fm = EditUserProfileForm(request.POST, instance=request.user)
                users=None
            if fm.is_valid():
                print("Form Validated")
                messages.success(request, "Profile Updated !")
                fm.save()
        else:
            if request.user.is_superuser == True:
                fm = EditAdminProfileForm(instance=request.user)
                users=User.objects.all()
            else:
                fm = EditUserProfileForm(instance=request.user)
                users=None
        return render(request,'webapp/profile.html', {"name":request.user.username, 'form':fm, 'users':users})
    else:
        return HttpResponseRedirect('/login/')

def user_logout(request):
    logout(request)
    messages.success(request,"Logged out successfully !!..")
    return HttpResponseRedirect('/login/')
    return render(request,'webapp/profile.html',{"form":fm})

def user_changepass(request):
    if request.method == "POST":
        fm = PasswordChangeForm(user = request.user, data=request.POST)
        if fm.is_valid():
            fm.save()
            update_session_auth_hash(request,fm.user)
            messages.success(request," Password Changed successfully !!..")
            return HttpResponseRedirect('/profile/')
    else:
        fm = PasswordChangeForm(user = request.user)
    return render(request,'webapp/changepass.html', {"form":fm})

def user_changepass1(request):
    if request.method == "POST":
        fm = SetPasswordForm(user = request.user, data=request.POST)
        if fm.is_valid():
            fm.save()
            update_session_auth_hash(request,fm.user)
            messages.success(request," Password Changed successfully !!..")
            return HttpResponseRedirect('/profile/')
    else:
        fm = SetPasswordForm(user = request.user)
    return render(request,'webapp/changepass1.html', {"form":fm})


def user_details(request, id):
    if request.user.is_authenticated:
        pi = User.objects.get(pk=id)
        fm = EditAdminProfileForm(instance=pi)
        return render(request,'webapp/user_details.html',{"form":fm})
    else:
        return HttpResponseRedirect('/login/')
