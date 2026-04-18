from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse_lazy
from django.views.decorators.http import require_http_methods
from .models import CustomUser
from .forms import SignUpForm, LoginForm, UserProfileForm


@require_http_methods(["GET", "POST"])
def signup(request):
    """User registration page."""
    if request.user.is_authenticated:
        return redirect('index')
    
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Log the user in after registration
            login(request, user)
            messages.success(request, 'Account created successfully! Welcome to OSINT Platform.')
            return redirect('index')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = SignUpForm()
    
    return render(request, 'accounts/signup.html', {'form': form})


@require_http_methods(["GET", "POST"])
def signin(request):
    """User login page."""
    if request.user.is_authenticated:
        return redirect('index')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = form.cleaned_data.get('user')
            remember_me = form.cleaned_data.get('remember_me')
            
            login(request, user)
            
            if not remember_me:
                # Set session to expire when browser closes
                request.session.set_expiry(0)
            
            messages.success(request, f'Welcome back, {user.username}!')
            next_url = request.GET.get('next', 'index')
            return redirect(next_url)
    else:
        form = LoginForm()
    
    return render(request, 'accounts/signin.html', {'form': form})


@require_http_methods(["GET"])
def logout_view(request):
    """User logout."""
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('accounts:signin')


@login_required(login_url='accounts:signin')
@require_http_methods(["GET", "POST"])
def profile(request):
    """User profile page."""
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
    else:
        form = UserProfileForm(instance=request.user)
    
    context = {
        'form': form,
        'user': request.user,
    }
    return render(request, 'accounts/profile.html', context)


@login_required(login_url='accounts:signin')
def dashboard(request):
    """User dashboard showing account information."""
    recent_investigations = request.user.investigationjob_set.all()[:10]
    
    context = {
        'recent_investigations': recent_investigations,
        'total_investigations': request.user.investigationjob_set.count(),
    }
    return render(request, 'accounts/dashboard.html', context)


@require_http_methods(["GET"])
def google_callback(request):
    """Callback for Google OAuth - handled by django-allauth"""
    # This is a placeholder. django-allauth handles the actual OAuth flow.
    # After successful authentication, user is redirected to 'index'
    return redirect('index')
