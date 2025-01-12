from django.shortcuts import redirect
from django.urls import reverse

class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        login_url = reverse('login')
        register_url = reverse('register')
        allowed_paths = [login_url, register_url]

        if not request.session.get('userid') and request.path not in allowed_paths:
            return redirect('login')
        
        if request.session.get('userid') and request.path in allowed_paths:
            return redirect('index') 

        response = self.get_response(request)
        return response
