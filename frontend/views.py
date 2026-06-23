from django.views.decorators.csrf import ensure_csrf_cookie
from django.shortcuts import render


@ensure_csrf_cookie
def index(request):
    """Serve the single-page demo UI and set the readable csrftoken cookie so
    the first state-changing request already has a token to echo."""
    return render(request, "index.html")
