from rest_framework.permissions import BasePermission
from rest_framework import permissions
class IsAdminUserRole(permissions.BasePermission):
    
    def has_permission(self, request, view):
        return bool(
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'admin'
        )

class IsDepartmentHead(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and
            request.user.role == "departmenthead"
        )
        
class IsAuthenticatedOrReadOnlyForPublic(permissions.BasePermission):
    def has_permission(self, request, view):
        # Allow GET requests for everyone
        if request.method in permissions.SAFE_METHODS:
            return True
        # Require authentication for other methods
        return request.user and request.user.is_authenticated
    
class SystemOpenPermission(BasePermission):
    """
    Permission to check if system/module is open
    """
    message = "The system/module is currently closed. Please contact administrator."
    
    def has_permission(self, request, view):
        # Admin can always access
        if request.user.is_authenticated and request.user.role == 'admin':
            return True
        
        # Get the module name from view or request
        module_name = self.get_module_name(view, request)
        
        # Check module access - IMPORTANT: Import SystemControl or use the model
        system_control = SystemControl.objects.first()  # This now works because SystemControl is imported
        if not system_control:
            return True  # No system control exists, allow access
        
        # If system is closed, block all non-admin users
        if not system_control.is_open:
            return False
        
        # Check specific module
        return SystemControl.get_module_status(module_name)
    
    def get_module_name(self, view, request):
        """Determine module name from view or request"""
        # Try to get from view attribute
        if hasattr(view, 'system_module'):
            return view.system_module
        
        # Try to get from URL pattern
        path = request.path.lower()
        if 'department' in path or 'dept' in path:
            return 'departmenthead'
        elif 'library' in path or 'librarian' in path:
            return 'librarian'
        elif 'cafeteria' in path:
            return 'cafeteria'
        elif 'dormitory' in path or 'dorm' in path:
            return 'dormitory'
        elif 'registrar' in path:
            return 'registrar'
        elif 'student' in path:
            return 'student'
        elif 'payment' in path:
            return 'payment'
        
        # Default to system check
        return None