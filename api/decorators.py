# decorators.py
from django.utils import timezone
from django.shortcuts import render
from functools import wraps
from .models import SystemControl

def system_open_required(view_func):
    """Decorator to check if system is open for function-based views"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Check if user is admin (always allowed)
        if request.user.is_authenticated and request.user.role == 'admin':
            return view_func(request, *args, **kwargs)
        
        # Get system control
        try:
            system_control = SystemControl.objects.first()
            if not system_control or system_control.is_currently_open():
                return view_func(request, *args, **kwargs)
            
            # System is closed
            return render(request, 'system_closed.html', {
                'message': 'The system is currently closed.',
                'maintenance_title': system_control.maintenance_title,
                'maintenance_message': system_control.maintenance_message,
                'next_open_time': system_control.calculate_next_open_time(),
                'closure_reasons': get_closure_reasons(system_control)
            })
        except Exception:
            # If there's an error, default to allowing access
            return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def system_module_required(module_name):
    """Decorator to check if specific module is open"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Check if user is admin (always allowed)
            if request.user.is_authenticated and request.user.role == 'admin':
                return view_func(request, *args, **kwargs)
            
            # Get system control
            try:
                system_control = SystemControl.objects.first()
                if not system_control:
                    return view_func(request, *args, **kwargs)
                
                # Check if system is currently open and module is accessible
                if system_control.is_currently_open() and system_control.is_module_open(module_name):
                    return view_func(request, *args, **kwargs)
                
                # System or module is closed
                return render(request, 'system_closed.html', {
                    'message': f'The {module_name.replace("_", " ").title()} module is currently unavailable.',
                    'maintenance_title': system_control.maintenance_title,
                    'maintenance_message': system_control.maintenance_message,
                    'next_open_time': system_control.calculate_next_open_time(),
                    'closure_reasons': get_closure_reasons(system_control)
                })
            except Exception:
                # If there's an error, default to allowing access
                return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    return decorator


def get_closure_reasons(system_control):
    """Get human-readable closure reasons"""
    reasons = []
    
    if not system_control.is_open:
        reasons.append("System manually closed by administrator")
    
    if system_control.start_date and system_control.end_date:
        current_date = timezone.now().date()
        if current_date < system_control.start_date:
            reasons.append(f"System starts on {system_control.start_date.strftime('%B %d, %Y')}")
        elif current_date > system_control.end_date:
            reasons.append(f"System ended on {system_control.end_date.strftime('%B %d, %Y')}")
    
    if system_control.allowed_months:
        current_month = timezone.now().month
        allowed_months = [int(m.strip()) for m in system_control.allowed_months.split(',') if m.strip()]
        if allowed_months and current_month not in allowed_months:
            month_names = ['January', 'February', 'March', 'April', 'May', 'June',
                          'July', 'August', 'September', 'October', 'November', 'December']
            allowed_month_names = [month_names[m-1] for m in allowed_months]
            reasons.append(f"System only available in: {', '.join(allowed_month_names)}")
    
    if system_control.allowed_days:
        current_day = timezone.now().weekday()
        allowed_days = [int(d.strip()) for d in system_control.allowed_days.split(',') if d.strip()]
        if allowed_days and current_day not in allowed_days:
            day_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
            allowed_day_names = [day_names[d] for d in allowed_days]
            reasons.append(f"System only available on: {', '.join(allowed_day_names)}")
    
    if system_control.daily_start_time and system_control.daily_end_time:
        current_time = timezone.now().time()
        if current_time < system_control.daily_start_time:
            reasons.append(f"System opens at {system_control.daily_start_time.strftime('%I:%M %p')}")
        elif current_time > system_control.daily_end_time:
            reasons.append(f"System closed at {system_control.daily_end_time.strftime('%I:%M %p')}. Opens tomorrow.")
    
    if system_control.scheduled_maintenance_start and system_control.scheduled_maintenance_end:
        current_time = timezone.now()
        if system_control.scheduled_maintenance_start <= current_time <= system_control.scheduled_maintenance_end:
            reasons.append(f"Scheduled maintenance until {system_control.scheduled_maintenance_end.strftime('%B %d, %Y at %I:%M %p')}")
    
    return reasons