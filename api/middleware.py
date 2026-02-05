from django.http import HttpResponse
from .models import SystemControl


class SystemOpenMiddleware:
    """
    If system is closed:
    - Only allow admin login/dashboard
    - All other pages, including React frontend, show "System Closed" HTML
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Paths always allowed for admin
        allowed_paths = [
            "/admin/login/",
            "/admin/",
            "/admin/logout/",
            "/api/system-controls/",  # Admin API
        ]

        for path in allowed_paths:
            if request.path.startswith(path):
                return self.get_response(request)

        # Get system status
        system_control = SystemControl.objects.first()
        system_open = system_control.is_open if system_control else True

        if system_open:
            # System open → everything works normally
            return self.get_response(request)

        # System closed → block everything else
        # If API request, return JSON
        if request.path.startswith("/api/"):
            from django.http import JsonResponse
            return JsonResponse({
    "system_closed": True,
    "message": "System is currently closed. Please contact administrator."
}, status=503)

        # Otherwise, return simple HTML page (for React frontend routes)
        html = """
        <!doctype html>
        <html>
          <head>
            <title>System Closed</title>
          </head>
          <body style="text-align: center; margin-top: 100px">
            <h1>🚫 System Currently Closed</h1>
            <p>The clearance system is currently closed by the administrator.</p>
            <p>Please try again later.</p>
          </body>
        </html>
        """
        return HttpResponse(html)
