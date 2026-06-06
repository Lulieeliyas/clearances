from rest_framework import status, generics, viewsets, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import AllowAny, IsAuthenticated
from .permissions import SystemOpenPermission
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import render
from django.shortcuts import render
from .decorators import system_open_required
from .models import User, ClearanceForm, Notification, ClearanceFormStatusHistory, Department, College, SystemControl, PasswordResetOTP,AuthorizedStudent,CSVStudentUpload,Building
from .serializers import (
    UserSerializer, RegisterSerializer, ClearanceFormSerializer,
    DepartmentSerializer, CollegeSerializer, SystemControlSerializer,
    ChangeProfileSerializer, AdminCreateUserSerializer, ChatRoomSerializer, MessageSerializer,CSVUploadSerializer,AuthorizedStudentSerializer,BuildingSerializer
)

from django.db.models import Count, Prefetch
from django.utils import timezone
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.http import StreamingHttpResponse, FileResponse
from rest_framework.decorators import action
from .models import PaymentMethod, StudentPayment, PaymentVerificationLog
from .serializers import (
    PaymentMethodSerializer, StudentPaymentSerializer,
    PaymentSubmissionSerializer, PaymentVerificationSerializer,
    PaymentVerificationLogSerializer
)
from .models import ClearanceCertificate
from rest_framework.parsers import MultiPartParser, FormParser
from django.db import transaction
from rest_framework.decorators import parser_classes
from .models import ChatRoom, Message
from django.contrib.auth.models import Group
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework.authtoken.models import Token
from django.utils import timezone
import json
import random
from datetime import datetime
from datetime import timedelta
from django.db.models import Q
from time import sleep
from django.db.models import Sum
from PIL import Image
import base64
import mimetypes
import qrcode
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import time
from django.core.files.base import ContentFile
from io import BytesIO
from django.db import transaction
from django.core.files.storage import default_storage
from django.http import HttpResponse
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import io
import os
import logging
logger = logging.getLogger(__name__)


User = get_user_model()

# ==================== PERMISSION CLASSES ====================
class IsAdminUserRole(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'admin'
        )

class IsDepartmentHead(permissions.BasePermission):
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

# ==================== AUTH VIEWS ====================

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        if request.data.get("role") != "student":
            return Response(
                {"error": "Only students can self-register"},
                status=403
            )

        try:
            data = request.data.copy()
            
            # Extract student ID for verification
            id_number = data.get("id_number", "").strip()
            
            if not id_number:
                return Response({
                    "error": "Student ID is required"
                }, status=400)
            
            # Check if student is in authorized list by ID ONLY
            authorized_student = AuthorizedStudent.objects.filter(
                id_number=id_number,
                is_active=True,
                is_registered=False
            ).first()
            
            if not authorized_student:
                return Response({
                    "error": "You are not authorized to register or already registered"
                }, status=403)
            
            if authorized_student.is_registered:
                return Response({
                    "error": "This student is already registered"
                }, status=400)
            
             # Validate building selection
            building_id = data.get("building")
            if not building_id:
                return Response({
                    "error": "Building selection is required",
                    "message": "Please select your dormitory building"
                }, status=400)
            
            try:
                building = Building.objects.get(id=building_id, is_active=True)
                data['building'] = building.id
                print(f"Student {id_number} will be assigned to building: {building.name} ({building.code})")
            except Building.DoesNotExist:
                return Response({
                    "error": "Invalid building selection",
                    "message": "The selected building does not exist or is not active"
                }, status=400)
            
            
            # Now validate other registration fields
            email = data.get("email")
            if not email:
                return Response({"error": "Email is required"}, status=400)
            
            # Check if email already exists in User model
            if User.objects.filter(email=email).exists():
                return Response({"error": "This email is already registered."}, status=400)
            
            # Handle department - it might be coming as a name, we need to convert to ID
            department_name = data.get("department")
            department = None
            if department_name:
                try:
                    # Try to get department by name first
                    department = Department.objects.get(name=department_name)
                    data['department'] = department.id
                except Department.DoesNotExist:
                    # If not found by name, maybe it's already an ID
                    try:
                        # Check if it's numeric (might be an ID)
                        if department_name.isdigit():
                            department = Department.objects.get(id=int(department_name))
                            data['department'] = department.id
                        else:
                            return Response(
                                {"error": f"Department '{department_name}' does not exist"},
                                status=400
                            )
                    except (ValueError, Department.DoesNotExist):
                        return Response(
                            {"error": f"Department '{department_name}' not found"},
                            status=400
                        )
            else:
                return Response({"error": "Department is required"}, status=400)
            
            # Handle college - ensure it's an integer
            college_id = data.get("college")
            college = None
            if college_id:
                try:
                    # Convert to integer if it's a string
                    if isinstance(college_id, str):
                        college_id = int(college_id)
                    college = College.objects.get(id=college_id)
                    data['college'] = college.id
                except (ValueError, College.DoesNotExist):
                    return Response(
                        {"error": f"College with ID '{college_id}' does not exist"},
                        status=400
                    )
            else:
                return Response({"error": "College is required"}, status=400)
            
            # Generate username if not provided
            if not data.get('username'):
                username = f"{authorized_student.first_name.lower().replace(' ', '_')}_{authorized_student.last_name.lower().replace(' ', '_')}_{id_number}"
                # Check if username already exists
                if User.objects.filter(username=username).exists():
                    # Add timestamp to make it unique
                    timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
                    username = f"{authorized_student.first_name.lower().replace(' ', '_')}_{authorized_student.last_name.lower().replace(' ', '_')}_{id_number}_{timestamp}"
                data['username'] = username
            
            # Use names from authorized student record, not from form
            data['first_name'] = authorized_student.first_name
            data['last_name'] = authorized_student.last_name
            
            serializer = RegisterSerializer(data=data)
            
            if serializer.is_valid():
                user = serializer.save()
                token, _ = Token.objects.get_or_create(user=user)
                
                # Update authorized student record with additional info
                authorized_student.email = email
                authorized_student.college = college
                authorized_student.department = department
                authorized_student.is_registered = True
                authorized_student.registered_user = user
                authorized_student.registration_date = timezone.now()
                authorized_student.save()
                
                # Verify building was saved correctly
                user.refresh_from_db()
                print(f"✅ Student {user.username} successfully registered:")
                print(f"   - Building assigned: {user.building.name if user.building else 'None'}")
                print(f"   - Building ID: {user.building.id if user.building else 'None'}")
                print(f"   - Building Code: {user.building.code if user.building else 'None'}")
                
                # Create notification for dormitory staff about new student
                dormitory_staff = User.objects.filter(
                    role='dormitory',
                    assigned_buildings=user.building,
                    is_active=True
                )
                
                for staff in dormitory_staff:
                    Notification.objects.create(
                        user=staff,
                        title="New Student Registered",
                        message=f"Student {user.get_full_name()} has been assigned to {user.building.name}",
                        notification_type="info"
                    )
                
                return Response({
                    "user": UserSerializer(user).data,
                    "token": token.key,
                    "building": {
                        "id": user.building.id if user.building else None,
                        "name": user.building.name if user.building else None,
                        "code": user.building.code if user.building else None
                    }
                }, status=201)
            else:
                # Return detailed validation errors
                return Response({
                    "errors": serializer.errors,
                    "message": "Registration failed. Please check your input."
                }, status=400)
        except Exception as e:
            print(f"❌ Registration error: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response({
                "error": str(e),
                "message": "An error occurred during registration"
            }, status=400)
            
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    role = request.data.get("role")
    password = request.data.get("password")

    if not role or not password:
        return Response({"error": "Role and password required"}, status=400)
    
    user = None

    # STUDENT LOGIN (email-based)
    if role == "student":
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email required"}, status=400)

        try:
            user = User.objects.get(email=email, role="student")
            if not user.check_password(password):
                return Response({"error": "Invalid credentials"}, status=401)
        except User.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=401)

    # STAFF LOGIN (username-based) - INCLUDES DEPARTMENT HEAD
    else:
        username = request.data.get("username")
        if not username:
            return Response({"error": "Username required"}, status=400)

        user = authenticate(username=username, password=password)
        if not user or user.role != role:
            return Response({"error": "Invalid credentials"}, status=401)
    
    # BLOCKED USER CHECK
    if user.is_blocked:
        return Response(
            {"error": "Account is blocked. Contact admin."},
            status=403
        )

    # TOKEN GENERATION
    token, _ = Token.objects.get_or_create(user=user)

    # Prepare user data with department as string (not object)
    user_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "department": user.department.name if user.department else None,  # Convert to string
        "department_id": user.department.id if user.department else None,
        "is_blocked": user.is_blocked,
        "first_name": user.first_name,
        "last_name": user.last_name,
    }

    return Response({
        "token": token.key,
        "user": user_data  # Use the serialized user_data
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    request.auth.delete()
    return Response({"message": "Logged out"})



# ==================== COLLEGE & DEPARTMENT VIEWS ====================
@api_view(["GET", "POST"])
@permission_classes([IsAuthenticatedOrReadOnlyForPublic])
def college_list(request):
    if request.method == "GET":
        colleges = College.objects.all()
        serializer = CollegeSerializer(colleges, many=True)
        return Response(serializer.data)
    elif request.method == "POST":
        if not request.user.is_authenticated or request.user.role != "admin":
            return Response({"error": "Admin access required"}, status=403)
        serializer = CollegeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=201)

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticatedOrReadOnlyForPublic])
def department_list(request):
    if request.method == "GET":
        departments = Department.objects.all()
        serializer = DepartmentSerializer(departments, many=True)
        return Response(serializer.data)
    elif request.method == "POST":
        if not request.user.is_authenticated or request.user.role != "admin":
            return Response({"error": "Admin access required"}, status=403)
        serializer = DepartmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=201)

# ==================== CLEARANCE FORM VIEWS ====================
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def submit_form(request):
    if request.user.role != "student":
        return Response({"error": "Only students can submit forms"}, status=403)
    
    data = request.data
    # Get student's building
    student_building = request.user.building
    if not student_building:
        return Response({
            "error": "No building assigned",
            "message": "You don't have a dormitory building assigned. Please contact admin."
        }, status=400)
    
    print(f"Student {request.user.username} submitting form - Building: {student_building.name} ({student_building.code})")
     # Create form with building information
    form = ClearanceForm.objects.create(
        student=request.user,
        full_name=data.get("full_name"),
        id_number=data.get("id_number"),
        academic_year=data.get("academic_year"),
        program_level=data.get("program_level"),
        enrollment_type=data.get("enrollment_type"),
        college=data.get("college"),
        department_name=data.get("department_name"),
        section=data.get("section"),
        last_attendance=data.get("last_attendance"),
        year=data.get("year"),
        semester=data.get("semester"),
        reason=data.get("reason"),
        student_building=student_building,
        student_building_code=student_building.code if student_building else None
    )
     # Find dormitory staff assigned to this building
    dormitory_staff = User.objects.filter(
        role='dormitory',
        assigned_buildings=student_building,
        is_active=True
    )
    # Create notification for each dormitory staff
    for staff in dormitory_staff:
        Notification.objects.create(
            user=staff,
            title="New Clearance Form",
            message=f"Student {request.user.get_full_name()} from {student_building.name} has submitted a clearance form.",
            clearance_form=form,
            notification_type="info"
        )
        print(f"Notification sent to dormitory staff: {staff.username}")

    return Response(
        {
            "message": "Clearance form submitted successfully",
            "form_id": form.id,
            "status": form.status,
            "building": {
                "id": student_building.id if student_building else None,
                "name": student_building.name if student_building else "No building assigned",
                "code": student_building.code if student_building else None
            },
            "assigned_dormitory_staff": [staff.username for staff in dormitory_staff]
        },
        status=status.HTTP_201_CREATED
    )
# In your views.py - Add this debug endpoint

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def debug_building_assignments(request):
    """Debug endpoint to check building assignments"""
    debug_info = {
        "buildings": [],
        "students_without_building": [],
        "dormitory_staff_without_buildings": [],
        "building_assignments": []
    }
    
    # Check all buildings
    buildings = Building.objects.all()
    for building in buildings:
        students = User.objects.filter(role='student', building=building, is_active=True)
        staff = User.objects.filter(role='dormitory', assigned_buildings=building, is_active=True)
        
        debug_info["buildings"].append({
            "id": building.id,
            "name": building.name,
            "code": building.code,
            "is_active": building.is_active,
            "student_count": students.count(),
            "assigned_staff_count": staff.count(),
            "assigned_staff": [s.username for s in staff]
        })
    
    # Check students without buildings
    students_no_building = User.objects.filter(role='student', building__isnull=True, is_active=True)
    debug_info["students_without_building"] = [
        {"id": s.id, "username": s.username, "email": s.email} 
        for s in students_no_building
    ]
    
    # Check dormitory staff without building assignments
    staff_no_buildings = User.objects.filter(
        role='dormitory', 
        is_active=True
    ).exclude(assigned_buildings__isnull=False)
    
    debug_info["dormitory_staff_without_buildings"] = [
        {"id": s.id, "username": s.username, "email": s.email} 
        for s in staff_no_buildings
    ]
    
    # Check form building assignments
    forms_with_buildings = ClearanceForm.objects.filter(
        student_building__isnull=False
    ).select_related('student_building')[:10]
    
    for form in forms_with_buildings:
        debug_info["building_assignments"].append({
            "form_id": form.id,
            "student": form.student.username if form.student else "Unknown",
            "building": form.student_building.name if form.student_building else "None",
            "building_code": form.student_building_code
        })
    
    return Response(debug_info)
@api_view(['GET'])
@permission_classes([AllowAny])
def get_active_buildings(request):
    """Public endpoint for registration form to get available buildings"""
    try:
        buildings = Building.objects.filter(is_active=True).annotate(
            student_count=Count('building_students', distinct=True)
        ).order_by('name')
        
        data = [{
            'id': b.id,
            'name': b.name,
            'code': b.code,
            'capacity': b.capacity,
            'address': b.address or '',
            'student_count': b.student_count
        } for b in buildings]
        
        return Response({
            'success': True,
            'buildings': data,
            'count': len(data)
        })
    except Exception as e:
        return Response({
            'error': str(e),
            'message': 'Failed to load buildings'
        }, status=500)
class StudentClearanceFormsView(APIView):
    permission_classes = [IsAuthenticated, SystemOpenPermission]

    def get(self, request):
        # Your normal logic
        return Response({"message": "Welcome to your dashboard"})

    def get(self, request):
        if request.user.role != "student":
            return Response({"error": "Only students can view their forms"}, status=403)
        
        forms = ClearanceForm.objects.filter(student=request.user)

        return Response([
            {
                "id": f.id,
                "full_name": f.full_name,
                "id_number": f.id_number,
                "program_level": f.program_level,
                "enrollment_type": f.enrollment_type,
                "college": f.college,
                "department": f.department_name,
                "year": f.year,
                "semester": f.semester,
                "status": f.status,
                "reason": f.reason,
                "created_at": f.created_at,
            }
            for f in forms
        ])

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_forms(request):
    if request.user.role not in ["admin", "departmenthead"]:
        return Response({"error": "Unauthorized"}, status=403)
    
    forms = ClearanceForm.objects.all().order_by("-id")
    return Response(ClearanceFormSerializer(forms, many=True).data)

# ==================== PATCH FORM ====================
@api_view(["PATCH"])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def patch_form(request, pk):
    """Update form status (admin only)"""
    form = get_object_or_404(ClearanceForm, pk=pk)
    
    # Get new status from request
    new_status = request.data.get("status")
    note = request.data.get("note", "")
    
    # Validate status
    valid_statuses = [choice[0] for choice in ClearanceForm.STATUS_CHOICES]
    if new_status and new_status not in valid_statuses:
        return Response({"error": "Invalid status"}, status=400)
    
    # Update form
    if new_status:
        form.status = new_status
    if note:
        form.note = note
    
    form.save()
    
    return Response({
        "message": "Form updated successfully",
        "form": ClearanceFormSerializer(form).data
    })

# In views.py, add this view function
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    """Get current authenticated user data"""
    user = request.user
    return Response({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "department": user.department.name if user.department else None,
        "department_id": user.department.id if user.department else None,
        "is_blocked": user.is_blocked,
        "is_active": user.is_active
    })

# ==================== DEPARTMENT HEAD VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def department_head_forms(request):
    if request.user.role != "departmenthead":
        return Response({"error": "Unauthorized"}, status=403)

    if not request.user.department:
        return Response({"error": "No department assigned to this user"}, status=400)

    # Get the department name from the user's department instance
    department_name = request.user.department.name
    
    if not department_name:
        return Response({"error": "Department not found"}, status=400)

    # Filter by department_name field (string) in ClearanceForm
    forms = ClearanceForm.objects.filter(
        department_name=department_name  # This is the string field
    ).order_by("-created_at")

    data = []
    for f in forms:
        data.append({
            "id": f.id,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "college": f.college,
            "department_name": f.department_name,
            "year": f.year,
            "semester": f.semester,
            "reason": f.reason,
            "status": f.status,
            "note": f.department_note or "",  # FIXED: Changed from f.note to f.department_note
            "created_at": f.created_at.strftime("%Y-%m-%d %H:%M"),
        })

    return Response(data)


# In your views.py, replace the existing department_head_action function with this:

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def department_head_action(request, pk):
    """Department Head action on clearance form"""
    print(f"Department head action called by user: {request.user.username}, role: {request.user.role}")
    print(f"Form ID: {pk}, Request data: {request.data}")

    # FIXED: Check for "departmenthead" (one word) instead of "department_head"
    if request.user.role != "departmenthead":
        return Response(
            {"error": "Unauthorized - Department Head access only"},
            status=403
        )

    try:
        form = get_object_or_404(ClearanceForm, pk=pk)
        print(f"Form found: ID={form.id}, Status={form.status}, Department={form.department_name}")
        
        # Check if user has a department assigned
        if not request.user.department:
            print(f"User has no department assigned")
            return Response({"error": "No department assigned to this user"}, status=400)

        # Get the department name from the user's department instance
        user_department_name = request.user.department.name
        form_department_name = form.department_name
        
        print(f"User department: {user_department_name}, Form department: {form_department_name}")
        
        # Compare departments - if they are the SAME, approve; if DIFFERENT, reject
        if form_department_name != user_department_name:
            # REJECT - Form is not from department head's department
            form.status = "rejected"
            form.department_note = f"Rejected - Student is not from {user_department_name} department. Form is from {form_department_name} department."
            form.updated_at = timezone.now()
            form.save()
            
            print(f"Form rejected. Status: {form.status}")
            
            # Create status history
            try:
                ClearanceFormStatusHistory.objects.create(
                    form=form,
                    status=form.status,
                    note=form.department_note,
                    changed_by=request.user
                )
            except Exception as e:
                print(f"Error creating status history: {e}")
            
            # Create notification for student
            if form.student:
                try:
                    Notification.objects.create(
                        user=form.student,
                        message=f"❌ Your clearance form has been REJECTED by Department Head. Reason: {form.department_note}",
                        notification_type="error",
                        clearance_form=form
                    )
                except Exception as e:
                    print(f"Error creating student notification: {e}")
            
            return Response({
                "message": f"Form rejected - Student is from different department",
                "status": form.status,
                "user_department": user_department_name,
                "form_department": form_department_name,
                "department_note": form.department_note,
                "timestamp": timezone.now().isoformat()
            })
        
        # If departments are the SAME, process the action
        # Check if form is in correct status
        if form.status != "pending_department":
            return Response({
                "error": f"Cannot process form with status: {form.status}. Form must be in 'pending_department' status.",
                "current_status": form.status
            }, status=400)

        action = request.data.get("action")
        note = request.data.get("note", "")
        print(f"Action requested: {action}, Note: {note}")

        if action == "approve":
            # APPROVE - Student is from your department
            form.department_approved_by = (
             f"{request.user.get_full_name()} "
             f"(Department Head – {form.department_name})"
                )
            form.department_approved_at = timezone.now()
            form.status = "approved_department"
            form.save()

            
            print(f"Form approved. Status: {form.status}")
            
            # Create status history
            try:
                ClearanceFormStatusHistory.objects.create(
                    form=form,
                    status=form.status,
                    note=form.department_note,
                    changed_by=request.user
                )
            except Exception as e:
                print(f"Error creating status history: {e}")
            
            # Create notification for student
            if form.student:
                try:
                    Notification.objects.create(
                        user=form.student,
                        message=f"✅ Your clearance form has been APPROVED by Department Head and sent to Librarian. Note: {form.department_note}",
                        notification_type="success",
                        clearance_form=form
                    )
                except Exception as e:
                    print(f"Error creating student notification: {e}")
                    
            # Send notification to Librarian
            try:
                librarian_users = User.objects.filter(role="librarian")
                for librarian in librarian_users:
                    Notification.objects.create(
                        user=librarian,
                        message=f"📋 New clearance form #{form.id} from {form.student.username if form.student else form.full_name} ready for library check",
                        notification_type="info",
                        clearance_form=form
                    )
            except Exception as e:
                print(f"Error creating librarian notification: {e}")
            
            message = f"Form approved and sent to Librarian"
            
        elif action == "reject":
            # REJECT (even though from same department)
            form.status = "rejected"
            form.department_note = note or f"Rejected by {request.user.username} - Department Head"
            form.updated_at = timezone.now()
            form.save()
            
            print(f"Form rejected. Status: {form.status}")
            
            # Create status history
            try:
                ClearanceFormStatusHistory.objects.create(
                    form=form,
                    status=form.status,
                    note=form.department_note,
                    changed_by=request.user
                )
            except Exception as e:
                print(f"Error creating status history: {e}")
            
            # Create notification for student
            if form.student:
                try:
                    Notification.objects.create(
                        user=form.student,
                        message=f"❌ Your clearance form has been REJECTED by Department Head. Note: {note}",
                        notification_type="error",
                        clearance_form=form
                    )
                except Exception as e:
                    print(f"Error creating student notification: {e}")
            
            message = "Form rejected"
            
        else:
            return Response({"error": "Invalid action. Use 'approve' or 'reject'"}, status=400)

        return Response({
            "message": message,
            "status": form.status,
            "form_id": form.id,
            "department_note": form.department_note,
            "timestamp": timezone.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error in department_head_action: {str(e)}")
        return Response({"error": str(e)}, status=500)


# ==================== SYSTEM CONTROL VIEWS ====================
class SystemControlViewSet(viewsets.ModelViewSet):
    queryset = SystemControl.objects.all()
    serializer_class = SystemControlSerializer
    permission_classes = [IsAuthenticated, IsAdminUserRole]

    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'status','check_module_access']:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAuthenticated, IsAdminUserRole]
        return [permission() for permission in permission_classes]
    
    @action(detail=False, methods=['get'])
    def status(self, request):
        """Get system status - accessible to all authenticated users"""
        return system_status(request)
    
    @action(detail=False, methods=['get'])
    def check_module_access(self, request):
        """Check module access - accessible to all authenticated users"""
        return check_module_access(request)

# ==================== ADMIN VIEWS ====================
class AdminStatsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]

    def get(self, request):
        total_forms = ClearanceForm.objects.count()
        approved_forms = ClearanceForm.objects.filter(status__icontains="approved").count()
        
        return Response({
            "total_users": User.objects.count(),
            "active_departments": Department.objects.count(),
            "total_colleges": College.objects.count(),
            "total_forms": total_forms,
            "approved_forms": approved_forms,
            "efficiency": round((approved_forms / total_forms) * 100, 2) if total_forms else 0
        })

@api_view(["POST"])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def admin_create_user(request):
    data = request.data

    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    role = data.get("role")
    department_id = data.get("department") 
    building_ids = data.get("assigned_buildings", []) 

    if not all([username, password, email, role]):
        return Response({"error": "Missing fields"}, status=400)

    if role == "student":
        return Response({"error": "Admin cannot create students"}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({"error": "Username exists"}, status=400)

    # Handle department assignment
    department_instance = None
    if role == "departmenthead":
        if not department_id:
            return Response(
                {"error": "Department Head must have a department"},
                status=400
            )
        
        try:
            department_instance = Department.objects.get(id=department_id)
             # Check if department already has a head
            existing_head = User.objects.filter(
                role='departmenthead',
                department=department_instance
            ).first()
            
            if existing_head:
                return Response({
                    "error": f"Department '{department_instance.name}' already has a head: {existing_head.username}"
                }, status=400)
        except Department.DoesNotExist:
            return Response({"error": "Department not found"}, status=404)
    
    # For dormitory role, handle building assignments
    elif role == "dormitory":
        # Validate building IDs if provided
        if building_ids:
            try:
                # Check if buildings exist and are active
                buildings = Building.objects.filter(id__in=building_ids, is_active=True)
                if buildings.count() != len(building_ids):
                    found_ids = set(buildings.values_list('id', flat=True))
                    missing_ids = set(building_ids) - found_ids
                    return Response({
                        "error": f"Some buildings not found or inactive: {list(missing_ids)}"
                    }, status=400)
            except Exception as e:
                return Response({"error": f"Invalid building IDs: {str(e)}"}, status=400)
    
    # For other roles, department should be None
    elif department_id:
        return Response(
            {"error": f"{role} role should not have a department assigned"},
            status=400
        )

    try:
        # Create user
        user = User.objects.create_user(
            username=username,
            password=password,
            email=email,
            role=role,
            department=department_instance
        )

        # Assign buildings for dormitory staff AFTER user is created
        if role == "dormitory" and building_ids:
            buildings = Building.objects.filter(id__in=building_ids, is_active=True)
            user.assigned_buildings.set(buildings)
            print(f"✅ Assigned {buildings.count()} buildings to {username}: {[b.name for b in buildings]}")

        Token.objects.get_or_create(user=user)

        # Return user data with building info
        user_data = UserSerializer(user).data
        if role == "dormitory":
            user_data['assigned_buildings'] = [
                {"id": b.id, "name": b.name, "code": b.code} 
                for b in user.assigned_buildings.all()
            ]

        return Response(user_data, status=201)
        
    except Exception as e:
        print(f"❌ Error creating user: {str(e)}")
        return Response({"error": str(e)}, status=500)
# ==================== ADMIN ACTIVITIES ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def admin_activities(request):
    """Get recent system activities for admin dashboard"""
    try:
        # Get recent notifications
        recent_notifications = Notification.objects.all().order_by('-created_at')[:10]
        
        # Get recent form actions
        recent_forms = ClearanceForm.objects.all().order_by('-created_at')[:5]
        
        # Get recent user activities
        recent_users = User.objects.filter(is_staff=True).order_by('-date_joined')[:3]
        
        activities = []
        
        # Add notification activities
        for notification in recent_notifications:
            activities.append({
                "id": notification.id,
                "user": notification.user.username if notification.user else "System",
                "action": notification.message,
                "target": "System" if not notification.clearance_form else f"Form #{notification.clearance_form.id}",
                "time": notification.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "time_ago": time_ago(notification.created_at),
                "icon": "notification",
                "color": "blue"
            })
        
        # Add form activities
        for form in recent_forms:
            activities.append({
                "id": form.id,
                "user": form.student.username if form.student else "Unknown",
                "action": f"Submitted clearance form - Status: {form.status}",
                "target": f"Form #{form.id}",
                "time": form.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "time_ago": time_ago(form.created_at),
                "icon": "file",
                "color": "green"
            })
        
        # Add user activities
        for user in recent_users:
            activities.append({
                "id": user.id,
                "user": "System",
                "action": f"New user registered: {user.username}",
                "target": f"Role: {user.role}",
                "time": user.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
                "time_ago": time_ago(user.date_joined),
                "icon": "user",
                "color": "purple"
            })
        
        # Sort by time (most recent first) and limit to 10
        activities.sort(key=lambda x: x["time"], reverse=True)
        activities = activities[:10]
        
        return Response(activities)
        
    except Exception as e:
        print(f"Error getting activities: {e}")
        # Return mock data if there's an error
        return Response(generate_mock_activities())

def time_ago(dt):
    """Helper function to format time ago"""
    now = timezone.now()
    diff = now - dt
    
    seconds = diff.total_seconds()
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours ago"
    elif seconds < 604800:
        return f"{int(seconds/86400)} days ago"
    else:
        return dt.strftime('%b %d, %Y')

def generate_mock_activities():
    """Generate mock activities for development"""
    now = timezone.now()
    return [
        {
            "id": 1,
            "user": "John Doe",
            "action": "approved clearance form",
            "target": "Form #1234",
            "time": (now - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'),
            "time_ago": "5 minutes ago",
            "icon": "check",
            "color": "green"
        },
        {
            "id": 2,
            "user": "Jane Smith",
            "action": "registered new dormitory due",
            "target": "Student STU2024001",
            "time": (now - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S'),
            "time_ago": "15 minutes ago",
            "icon": "home",
            "color": "purple"
        },
        {
            "id": 3,
            "user": "Admin",
            "action": "created new department",
            "target": "Computer Science",
            "time": (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
            "time_ago": "1 hour ago",
            "icon": "shop",
            "color": "blue"
        },
        {
            "id": 4,
            "user": "System",
            "action": "auto-generated report",
            "target": "Weekly Efficiency",
            "time": (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'),
            "time_ago": "2 hours ago",
            "icon": "line-chart",
            "color": "orange"
        },
        {
            "id": 5,
            "user": "Librarian",
            "action": "checked book dues",
            "target": "5 students",
            "time": (now - timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S'),
            "time_ago": "3 hours ago",
            "icon": "book",
            "color": "green"
        },
    ]

# ==================== OTHER VIEWS ====================
class AllUsersListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUserRole]

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUserRole]
    
    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            
            if serializer.is_valid():
                self.perform_update(serializer)
                return Response({
                    "message": "User updated successfully",
                    "user": serializer.data
                })
            else:
                # Log validation errors
                print(f"Validation errors: {serializer.errors}")
                return Response({
                    "error": "Validation failed",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            print(f"Error updating user: {str(e)}")
            return Response({
                "error": "Failed to update user",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def patch(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

# ==================== NOTIFICATIONS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def notifications_stream(request):
    def event_stream():
        last_id = 0
        while True:
            notifications = Notification.objects.filter(
                user=request.user,
                id__gt=last_id
            )
            for n in notifications:
                yield f"data: {json.dumps({'message': n.message, 'time': str(n.created_at)})}\n\n"
                last_id = n.id
            sleep(3)

    return StreamingHttpResponse(event_stream(), content_type="text/event-stream")

# ==================== LIBRARIAN VIEWS ====================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def librarian_forms(request):
    if request.user.role != "librarian":
        return Response({"error": "Unauthorized - Librarian access only"}, status=403)

    # Get forms that are approved by department head and pending library check
    forms = ClearanceForm.objects.filter(status="approved_department").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "note": f.note if hasattr(f, 'note') else "",
            "library_note": f.library_note if hasattr(f, 'library_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])

def check_student_book_status(student_id):
    """No automatic checking - verification only"""
    return {
        "has_borrowed_books": False,
        "has_due_books": False,
        "books": [],
        "total_fines": 0,
        "can_approve": True  # Let librarian decide
    }

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def check_book_status_api(request, student_id):
    """API endpoint to check book status"""
    if request.user.role not in ["librarian", "admin"]:
        return Response({"error": "Unauthorized"}, status=403)

    try:
        # Find student by ID or ID number
        student = None
        
        # Try by numeric ID
        if student_id.isdigit():
            try:
                student = User.objects.get(id=int(student_id), role="student")
            except User.DoesNotExist:
                pass
        
        # If not found by ID, try by ID number
        if not student:
            try:
                student = User.objects.get(id_number=student_id, role="student")
            except User.DoesNotExist:
                pass
        
        if not student:
            return Response({"error": "Student not found"}, status=404)

        # Check book status using helper function
        book_status = check_student_book_status(student_id)
        
        if not book_status:
            return Response({"error": "Could not check book status"}, status=500)
        
        # Add student info to response
        book_status.update({
            "student_id": student.id,
            "student_name": student.get_full_name() or student.username,
            "id_number": student.id_number if hasattr(student, 'id_number') else student_id,
            "email": student.email
        })
        
        return Response(book_status)

    except Exception as e:
        print(f"Error checking book status API: {e}")
        return Response({"error": str(e)}, status=500)



# ==================== CAFETERIA VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def cafeteria_forms(request):
    if request.user.role != "cafeteria":
        return Response({"error": "Unauthorized - Cafeteria access only"}, status=403)

    # Get forms that are approved by librarian and pending cafeteria check
    forms = ClearanceForm.objects.filter(status="approved_library").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "note": f.note if hasattr(f, 'note') else "",
            "library_note": f.library_note if hasattr(f, 'library_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])

def check_student_meal_dues(student_id):
    """Manual verification only - no automatic checking"""
    return {
        "has_meal_dues": False,  # Let cafeteria officer decide manually
        "dues": [],
        "total_amount": 0,
        "can_approve": True  # Manual decision
    }

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def check_meal_dues_api(request, student_id):
    """API endpoint to check meal dues - Manual verification only"""
    if request.user.role not in ["cafeteria", "admin"]:
        return Response({"error": "Unauthorized"}, status=403)

    try:
        # Find student by ID or ID number
        student = None
        
        # Try by numeric ID
        if student_id.isdigit():
            try:
                student = User.objects.get(id=int(student_id), role="student")
            except User.DoesNotExist:
                pass
        
        # If not found by ID, try by ID number
        if not student:
            try:
                student = User.objects.get(id_number=student_id, role="student")
            except User.DoesNotExist:
                pass
        
        if not student:
            return Response({"error": "Student not found"}, status=404)

        # Return empty result - manual verification only
        meal_dues = {
            "has_meal_dues": False,
            "dues": [],
            "total_amount": 0,
            "can_approve": True,
            "student_id": student.id,
            "student_name": student.get_full_name() or student.username,
            "id_number": student.id_number if hasattr(student, 'id_number') else student_id,
            "email": student.email,
            "note": "Manual verification required by cafeteria officer"
        }
        
        return Response(meal_dues)

    except Exception as e:
        print(f"Error checking meal dues API: {e}")
        return Response({"error": str(e)}, status=500)


# ==================== LIBRARIAN VIEWS ====================

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def librarian_action(request, pk):
    """Librarian action on clearance form with payment requirement"""
    if request.user.role != "librarian":
        return Response({"error": "Unauthorized - Librarian access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)
    
    # Check if form is in correct status
    if form.status != "approved_department":
        return Response(
            {"error": "Form must be approved by department head first"},
            status=400
        )

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")
    
    if action == "approve":
        # APPROVE LOGIC
        form.library_approved_by = (
         f"{request.user.get_full_name()} (Chief Librarian)"
)
        form.library_approved_at = timezone.now()
        form.status = "approved_library"
        form.save()


        
        # Create notification for student
        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Librarian",
                message=f"✅ Your clearance form #{form.id} has been APPROVED by Librarian and sent to Cafeteria. Note: {form.library_note}",
                clearance_form=form
            )
            
    elif action == "reject":
        if requires_payment:
            # REJECT WITH PAYMENT REQUIREMENT
            form.status = "requires_library_payment"
            payment_note = f"Payment required: {payment_amount} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.library_note = payment_note
            form.save()
            
            # Generate payment link
            payment_link = f"/student/payments?form_id={form.id}&department=library&amount={payment_amount}"
            
            # Create detailed notification with payment link
            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Library Payment Required",
                    message=f"❌ Your clearance form #{form.id} requires LIBRARY PAYMENT. Reason: {payment_reason}. Amount: {payment_amount} ETB. Click here to make payment: {payment_link}",
                    clearance_form=form
                )
                
            # Send email notification with payment link
            if form.student and form.student.email:
                try:
                    send_mail(
                        subject="Clearance Form - Library Payment Required",
                        message=f"""
Dear {form.full_name},

Your clearance form #{form.id} has been reviewed by the Librarian.

REASON FOR REJECTION: {note}

PAYMENT REQUIRED: {payment_amount} ETB
PAYMENT REASON: {payment_reason}

REQUIRED ACTION: Please make library payment to proceed with your clearance.

PAYMENT LINK: http://127.0.0.1:3000{payment_link}

Once payment is verified, your form will be automatically approved.

Best regards,
University Clearance System
                        """,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[form.student.email],
                        fail_silently=True,
                    )
                except Exception as e:
                    print(f"Email sending error: {e}")
            
            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link,
                "amount": payment_amount,
                "reason": payment_reason
            })
        else:
            # REGULAR REJECTION (no payment required)
            form.status = "rejected"
            form.library_note = f"Rejected by {request.user.username} - Librarian: {note}"
            form.save()
            
            # Create notification for student
            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Librarian",
                    message=f"❌ Your clearance form #{form.id} has been REJECTED by Librarian. Reason: {note}",
                    clearance_form=form
                )
    else:
        return Response({"error": "Invalid action. Use 'approve' or 'reject'"}, status=400)

    form.save()
    
    return Response({
        "message": f"Form {action}d successfully",
        "status": form.status,
        "note": form.library_note,
        "requires_payment": requires_payment,
        "payment_department": "library" if requires_payment else None,
        "payment_amount": payment_amount if requires_payment else None
    })


# ==================== CAFETERIA VIEWS ====================
@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def cafeteria_action(request, pk):
    """Cafeteria action on clearance form - SENDS TO PSYCHOLOGY NEXT"""
    if request.user.role != "cafeteria":
        return Response(
            {"error": "Unauthorized - Cafeteria access only"},
            status=403
        )

    form = get_object_or_404(ClearanceForm, pk=pk)

    # Must be approved by Library first
    if form.status != "approved_library":
        return Response(
            {"error": "Form must be approved by Library first"},
            status=400
        )

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    # ================= APPROVE =================
    if action == "approve":
        form.cafeteria_approved_by = (
            f"{request.user.get_full_name()} (Cafeteria Manager)"
        )
        form.cafeteria_approved_at = timezone.now()
        form.status = "approved_cafeteria"  # Send to Psychology

        form.cafeteria_note = "Approved"
        if note:
            form.cafeteria_note += f": {note}"

        form.save()

        # Notify student
        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Cafeteria",
                message=(
                    f"✅ Your clearance form #{form.id} has been APPROVED "
                    f"by Cafeteria and sent to Psychology. "
                    f"Note: {form.cafeteria_note}"
                ),
                clearance_form=form
            )
        
        # Send notification to Psychology department
        psychology_users = User.objects.filter(role='psychology', is_active=True)
        for psych in psychology_users:
            Notification.objects.create(
                user=psych,
                title="New Form for Psychology Review",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for Psychology review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Cafeteria - Sent to Psychology",
            "status": form.status,
            "approved_by": form.cafeteria_approved_by,
            "next_department": "psychology"
        })

    # ================= REJECT =================
    elif action == "reject":

        # ---- Reject with payment ----
        if requires_payment:
            form.status = "requires_cafeteria_payment"

            payment_note = (
                f"Payment required: "
                f"{payment_amount if payment_amount else 'To be determined'} ETB. "
                f"Reason: {payment_reason}"
            )
            if note:
                payment_note = f"{note}. {payment_note}"

            form.cafeteria_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=cafeteria"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Cafeteria Payment Required",
                    message=(
                        f"❌ Your clearance form #{form.id} requires "
                        f"CAFETERIA PAYMENT.\n"
                        f"Amount: {payment_amount or 'TBD'} ETB\n"
                        f"Reason: {payment_reason}\n"
                        f"Pay here: {payment_link}"
                    ),
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link,
                "amount": payment_amount,
                "reason": payment_reason
            })

        # ---- Normal rejection ----
        else:
            form.status = "rejected"
            form.cafeteria_note = (
                f"Rejected by {request.user.get_full_name()} "
                f"(Cafeteria): {note}"
            )
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Cafeteria",
                    message=(
                        f"❌ Your clearance form #{form.id} has been "
                        f"REJECTED by Cafeteria.\nReason: {note}"
                    ),
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.cafeteria_note
            })

    # ================= INVALID ACTION =================
    return Response(
        {"error": "Invalid action. Use 'approve' or 'reject'"},
        status=400
    )

# ==================== PSYCHOLOGY VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def psychology_forms(request):
    """Get forms that are approved by cafeteria and pending psychology check"""
    if request.user.role != "psychology":
        return Response({"error": "Unauthorized - Psychology access only"}, status=403)

    forms = ClearanceForm.objects.filter(status="approved_cafeteria").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "cafeteria_note": f.cafeteria_note if hasattr(f, 'cafeteria_note') else "",
            "psychology_note": f.psychology_note if hasattr(f, 'psychology_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def psychology_action(request, pk):
    """Psychology action on clearance form - SENDS TO SPORT MASTER NEXT"""
    if request.user.role != "psychology":
        return Response({"error": "Unauthorized - Psychology access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    # Must be approved by Cafeteria first
    if form.status != "approved_cafeteria":
        return Response(
            {"error": "Form must be approved by Cafeteria first"},
            status=400
        )

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    if action == "approve":
        form.psychology_approved_by = (
            f"{request.user.get_full_name()} (Psychology)"
        )
        form.psychology_approved_at = timezone.now()
        form.status = "approved_psychology"  # Send to Sport Master

        form.psychology_note = "Approved"
        if note:
            form.psychology_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Psychology",
                message=f"✅ Your form #{form.id} has been APPROVED by Psychology and sent to Sport Master. Note: {form.psychology_note}",
                clearance_form=form
            )
        
        # Notify Sport Master
        sport_users = User.objects.filter(role='sportmaster', is_active=True)
        for sport in sport_users:
            Notification.objects.create(
                user=sport,
                title="New Form for Sport Master",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for Sport Master review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Psychology - Sent to Sport Master",
            "status": form.status,
            "approved_by": form.psychology_approved_by,
            "next_department": "sportmaster"
        })

    elif action == "reject":
        if requires_payment:
            form.status = "requires_psychology_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.psychology_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=psychology"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Psychology Payment Required",
                    message=f"❌ Form #{form.id} requires PSYCHOLOGY PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.psychology_note = f"Rejected by {request.user.get_full_name()} (Psychology): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Psychology",
                    message=f"❌ Your form #{form.id} has been REJECTED by Psychology.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.psychology_note
            })

    return Response({"error": "Invalid action"}, status=400)


# ==================== SPORT MASTER VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def sportmaster_forms(request):
    """Get forms that are approved by psychology and pending sport master check"""
    if request.user.role != "sportmaster":
        return Response({"error": "Unauthorized - Sport Master access only"}, status=403)

    forms = ClearanceForm.objects.filter(status="approved_psychology").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "psychology_note": f.psychology_note if hasattr(f, 'psychology_note') else "",
            "sportmaster_note": f.sportmaster_note if hasattr(f, 'sportmaster_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def sportmaster_action(request, pk):
    """Sport Master action on clearance form - SENDS TO CAMPUS POLICE NEXT"""
    if request.user.role != "sportmaster":
        return Response({"error": "Unauthorized - Sport Master access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    if form.status != "approved_psychology":
        return Response({"error": "Form must be approved by Psychology first"}, status=400)

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    if action == "approve":
        form.sportmaster_approved_by = f"{request.user.get_full_name()} (Sport Master)"
        form.sportmaster_approved_at = timezone.now()
        form.status = "approved_sportmaster"  # Send to Campus Police

        form.sportmaster_note = "Approved"
        if note:
            form.sportmaster_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Sport Master",
                message=f"✅ Your form #{form.id} has been APPROVED by Sport Master and sent to Campus Police. Note: {form.sportmaster_note}",
                clearance_form=form
            )
        
        # Notify Campus Police
        police_users = User.objects.filter(role='campuspolice', is_active=True)
        for police in police_users:
            Notification.objects.create(
                user=police,
                title="New Form for Campus Police",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for Campus Police review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Sport Master - Sent to Campus Police",
            "status": form.status,
            "approved_by": form.sportmaster_approved_by,
            "next_department": "campuspolice"
        })

    elif action == "reject":
        if requires_payment:
            form.status = "requires_sportmaster_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.sportmaster_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=sportmaster"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Sport Master Payment Required",
                    message=f"❌ Form #{form.id} requires SPORT MASTER PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.sportmaster_note = f"Rejected by {request.user.get_full_name()} (Sport Master): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Sport Master",
                    message=f"❌ Your form #{form.id} has been REJECTED by Sport Master.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.sportmaster_note
            })

    return Response({"error": "Invalid action"}, status=400)

# ==================== CAMPUS POLICE VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def campuspolice_forms(request):
    """Get forms that are approved by sport master and pending campus police check"""
    if request.user.role != "campuspolice":
        return Response({"error": "Unauthorized - Campus Police access only"}, status=403)

    forms = ClearanceForm.objects.filter(status="approved_sportmaster").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "sportmaster_note": f.sportmaster_note if hasattr(f, 'sportmaster_note') else "",
            "campuspolice_note": f.campuspolice_note if hasattr(f, 'campuspolice_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def campuspolice_action(request, pk):
    """Campus Police action on clearance form - SENDS TO COOPERATION SHARING NEXT"""
    if request.user.role != "campuspolice":
        return Response({"error": "Unauthorized - Campus Police access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    if form.status != "approved_sportmaster":
        return Response({"error": "Form must be approved by Sport Master first"}, status=400)

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    if action == "approve":
        form.campuspolice_approved_by = f"{request.user.get_full_name()} (Campus Police)"
        form.campuspolice_approved_at = timezone.now()
        form.status = "approved_campuspolice"  # Send to Cooperation Sharing

        form.campuspolice_note = "Approved"
        if note:
            form.campuspolice_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Campus Police",
                message=f"✅ Your form #{form.id} has been APPROVED by Campus Police and sent to Cooperation Sharing. Note: {form.campuspolice_note}",
                clearance_form=form
            )
        
        # Notify Cooperation Sharing
        coop_users = User.objects.filter(role='cooperationsharing', is_active=True)
        for coop in coop_users:
            Notification.objects.create(
                user=coop,
                title="New Form for Cooperation Sharing",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for Cooperation Sharing review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Campus Police - Sent to Cooperation Sharing",
            "status": form.status,
            "approved_by": form.campuspolice_approved_by,
            "next_department": "cooperationsharing"
        })

    elif action == "reject":
        if requires_payment:
            form.status = "requires_campuspolice_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.campuspolice_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=campuspolice"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Campus Police Payment Required",
                    message=f"❌ Form #{form.id} requires CAMPUS POLICE PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.campuspolice_note = f"Rejected by {request.user.get_full_name()} (Campus Police): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Campus Police",
                    message=f"❌ Your form #{form.id} has been REJECTED by Campus Police.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.campuspolice_note
            })

    return Response({"error": "Invalid action"}, status=400)
# ==================== COOPERATION SHARING VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def cooperationsharing_forms(request):
    """Get forms that are approved by campus police and pending cooperation sharing check"""
    if request.user.role != "cooperationsharing":
        return Response({"error": "Unauthorized - Cooperation Sharing access only"}, status=403)

    # FIXED: Use correct status - approved_campuspolice should go to cooperation sharing
    forms = ClearanceForm.objects.filter(status="approved_campuspolice").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "campuspolice_note": f.campuspolice_note if hasattr(f, 'campuspolice_note') else "",
            "cooperationsharing_note": f.cooperationsharing_note if hasattr(f, 'cooperationsharing_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def cooperationsharing_action(request, pk):
    """Cooperation Sharing action on clearance form - SENDS TO DOP CORDINATOR NEXT"""
    if request.user.role != "cooperationsharing":
        return Response({"error": "Unauthorized - Cooperation Sharing access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    # Must be approved by Campus Police first
    if form.status != "approved_campuspolice":
        return Response(
            {"error": "Form must be approved by Campus Police first"},
            status=400
        )

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    # ================= APPROVE =================
    if action == "approve":
        # FIXED: Use correct field names
        form.cooperationsharing_approved_by = f"{request.user.get_full_name()} (Cooperation Sharing)"
        form.cooperationsharing_approved_at = timezone.now()
        form.status = "approved_cooperationsharing"  # Send to DOP Cordinator

        form.cooperationsharing_note = "Approved"
        if note:
            form.cooperationsharing_note += f": {note}"

        form.save()

        # Notify student
        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Cooperation Sharing",
                message=f"✅ Your form #{form.id} has been APPROVED by Cooperation Sharing and sent to DOP Cordinator. Note: {form.cooperationsharing_note}",
                clearance_form=form
            )
        
        # Notify DOP Cordinator
        dop_users = User.objects.filter(role='dopcordinator', is_active=True)
        for dop in dop_users:
            Notification.objects.create(
                user=dop,
                title="New Form for DOP Cordinator",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for DOP Cordinator review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Cooperation Sharing - Sent to DOP Cordinator",
            "status": form.status,
            "approved_by": form.cooperationsharing_approved_by,
            "next_department": "dopcordinator"
        })

    # ================= REJECT =================
    elif action == "reject":
        if requires_payment:
            form.status = "requires_cooperationsharing_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.cooperationsharing_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=cooperationsharing"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Cooperation Sharing Payment Required",
                    message=f"❌ Form #{form.id} requires COOPERATION SHARING PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.cooperationsharing_note = f"Rejected by {request.user.get_full_name()} (Cooperation Sharing): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Cooperation Sharing",
                    message=f"❌ Your form #{form.id} has been REJECTED by Cooperation Sharing.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.cooperationsharing_note
            })

    return Response({"error": "Invalid action. Use 'approve' or 'reject'"}, status=400)
    """Cooperation Sharing action on clearance form - SENDS TO DOP CORDINATOR NEXT"""
    if request.user.role != "cooperationsharing":
        return Response({"error": "Unauthorized - Cooperation Sharing access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    if form.status != "approved_campuspolice":
        return Response({"error": "Form must be approved by Campus Police first"}, status=400)

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    if action == "approve":
        # FIXED: Use correct field name 'cooperationsharing_approved_by' instead of 'coastsharing_approved_by'
        form.cooperationsharing_approved_by = f"{request.user.get_full_name()} (Cooperation Sharing)"
        form.cooperationsharing_approved_at = timezone.now()
        form.status = "approved_cooperationsharing"  # Send to DOP Cordinator

        form.cooperationsharing_note = "Approved"
        if note:
            form.cooperationsharing_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Cooperation Sharing",
                message=f"✅ Your form #{form.id} has been APPROVED by Cooperation Sharing and sent to DOP Cordinator. Note: {form.cooperationsharing_note}",
                clearance_form=form
            )
        
        # Notify DOP Cordinator
        dop_users = User.objects.filter(role='dopcordinator', is_active=True)
        for dop in dop_users:
            Notification.objects.create(
                user=dop,
                title="New Form for DOP Cordinator",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for DOP Cordinator review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Cooperation Sharing",
            "status": form.status,
            "approved_by": form.cooperationsharing_approved_by,
            "next_department": "dopcordinator"
        })

    elif action == "reject":
        if requires_payment:
            form.status = "requires_cooperationsharing_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.cooperationsharing_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=cooperationsharing"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Cooperation Sharing Payment Required",
                    message=f"❌ Form #{form.id} requires COOPERATION SHARING PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.cooperationsharing_note = f"Rejected by {request.user.get_full_name()} (Cooperation Sharing): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Cooperation Sharing",
                    message=f"❌ Your form #{form.id} has been REJECTED by Cooperation Sharing.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.cooperationsharing_note
            })

    return Response({"error": "Invalid action"}, status=400)
    """Cooperation Sharing action on clearance form - SENDS TO DOP CORDINATOR NEXT"""
    if request.user.role != "cooperationsharing":
        return Response({"error": "Unauthorized - Cooperation Sharing access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    if form.status != "approved_campuspolice":
        return Response({"error": "Form must be approved by Campus Police first"}, status=400)

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    if action == "approve":
        form.coastsharing_approved_by = f"{request.user.get_full_name()} (Coast Sharing)"
        form.coastsharing_approved_at = timezone.now()
        form.status = "approved_coastsharing"  # Send to DOP Cordinator

        form.coastsharing_note = "Approved"
        if note:
            form.coastsharing_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Coast  Sharing",
                message=f"✅ Your form #{form.id} has been APPROVED by Cooperation Sharing and sent to DOP Cordinator. Note: {form.cooperationsharing_note}",
                clearance_form=form
            )
        
        # Notify DOP Cordinator
        dop_users = User.objects.filter(role='dopcordinator', is_active=True)
        for dop in dop_users:
            Notification.objects.create(
                user=dop,
                title="New Form for DOP Cordinator",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for DOP Cordinator review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Coast  Sharing",
            "status": form.status,
            "approved_by": form.coastsharing_approved_by,
            "next_department": "dopcordinator"
        })

    elif action == "reject":
        if requires_payment:
            form.status = "requires_coastsharing_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.cooperationsharing_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=cooperationsharing"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Coast Sharing Payment Required",
                    message=f"❌ Form #{form.id} requires COOPERATION SHARING PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.coastsharing_note  = f"Rejected by {request.user.get_full_name()} (Coast Sharing): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Coast Sharing",
                    message=f"❌ Your form #{form.id} has been REJECTED by Coast Sharing.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.coastsharing_note
            })

    return Response({"error": "Invalid action"}, status=400)

# ==================== DOP CORDINATOR VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dopcordinator_forms(request):
    """Get forms that are approved by cooperation sharing and pending DOP cordinator check"""
    if request.user.role != "dopcordinator":
        return Response({"error": "Unauthorized - DOP Cordinator access only"}, status=403)

    # FIXED: Use correct status - approved_cooperationsharing
    forms = ClearanceForm.objects.filter(status="approved_cooperationsharing").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "cooperationsharing_note": f.cooperationsharing_note if hasattr(f, 'cooperationsharing_note') else "",
            "dopcordinator_note": f.dopcordinator_note if hasattr(f, 'dopcordinator_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def dopcordinator_action(request, pk):
    """DOP Cordinator action on clearance form - SENDS TO STUDENT AFFAIRS NEXT"""
    if request.user.role != "dopcordinator":
        return Response({"error": "Unauthorized - DOP Cordinator access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    # FIXED: Check for correct status 'approved_cooperationsharing'
    if form.status != "approved_cooperationsharing":
        return Response({"error": "Form must be approved by Cooperation Sharing first"}, status=400)

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    if action == "approve":
        # FIXED: Use correct field name 'dopcoordinator_approved_by' (note the spelling: coordinator with 'o')
        form.dopcoordinator_approved_by = f"{request.user.get_full_name()} (DOP Coordinator)"
        form.dopcoordinator_approved_at = timezone.now()
        form.status = "approved_dopcordinator"  # Send to Student Affairs

        form.dopcordinator_note = "Approved"
        if note:
            form.dopcordinator_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by DOP Cordinator",
                message=f"✅ Your form #{form.id} has been APPROVED by DOP Cordinator and sent to Student Affairs. Note: {form.dopcordinator_note}",
                clearance_form=form
            )
        
        # Notify Student Affairs
        affairs_users = User.objects.filter(role='studentaffairs', is_active=True)
        for affairs in affairs_users:
            Notification.objects.create(
                user=affairs,
                title="New Form for Student Affairs",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for Student Affairs review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by DOP Cordinator",
            "status": form.status,
            "approved_by": form.dopcoordinator_approved_by,
            "next_department": "studentaffairs"
        })

    elif action == "reject":
        if requires_payment:
            form.status = "requires_dopcordinator_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.dopcordinator_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=dopcordinator"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="DOP Cordinator Payment Required",
                    message=f"❌ Form #{form.id} requires DOP CORDINATOR PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.dopcordinator_note = f"Rejected by {request.user.get_full_name()} (DOP Cordinator): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by DOP Cordinator",
                    message=f"❌ Your form #{form.id} has been REJECTED by DOP Cordinator.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.dopcordinator_note
            })

    return Response({"error": "Invalid action"}, status=400)
# ==================== STUDENT AFFAIRS VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def studentaffairs_forms(request):
    """Get forms that are approved by DOP cordinator and pending student affairs check"""
    if request.user.role != "studentaffairs":
        return Response({"error": "Unauthorized - Student Affairs access only"}, status=403)

    forms = ClearanceForm.objects.filter(status="approved_dopcordinator").order_by('-created_at')

    return Response([
        {
            "id": f.id,
            "student_id": f.student.id if f.student else None,
            "student_email": f.student.email if f.student else None,
            "full_name": f.full_name,
            "id_number": f.id_number,
            "department_name": f.department_name,
            "college": f.college,
            "program_level": f.program_level,
            "enrollment_type": f.enrollment_type,
            "year": f.year,
            "semester": f.semester,
            "section": f.section,
            "reason": f.reason,
            "status": f.status,
            "dopcordinator_note": f.dopcordinator_note if hasattr(f, 'dopcordinator_note') else "",
            "studentaffairs_note": f.studentaffairs_note if hasattr(f, 'studentaffairs_note') else "",
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        } for f in forms
    ])

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def studentaffairs_action(request, pk):
    """Student Affairs action on clearance form - SENDS TO DORMITORY NEXT"""
    if request.user.role != "studentaffairs":
        return Response({"error": "Unauthorized - Student Affairs access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    if form.status != "approved_dopcordinator":
        return Response({"error": "Form must be approved by DOP Cordinator first"}, status=400)

    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    if action == "approve":
        form.studentaffairs_approved_by = f"{request.user.get_full_name()} (Student Affairs)"
        form.studentaffairs_approved_at = timezone.now()
        form.status = "approved_studentaffairs"  # Send to Dormitory

        form.studentaffairs_note = "Approved"
        if note:
            form.studentaffairs_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Form Approved by Student Affairs",
                message=f"✅ Your form #{form.id} has been APPROVED by Student Affairs and sent to Dormitory. Note: {form.studentaffairs_note}",
                clearance_form=form
            )
        
        # Notify Dormitory
        dorm_users = User.objects.filter(role='dormitory', is_active=True)
        for dorm in dorm_users:
            Notification.objects.create(
                user=dorm,
                title="New Form for Dormitory",
                message=f"📋 Form #{form.id} from {form.full_name} is ready for Dormitory review",
                clearance_form=form
            )

        return Response({
            "message": "Approved by Student Affairs - Sent to Dormitory",
            "status": form.status,
            "approved_by": form.studentaffairs_approved_by,
            "next_department": "dormitory"
        })

    elif action == "reject":
        if requires_payment:
            form.status = "requires_studentaffairs_payment"
            payment_note = f"Payment required: {payment_amount or 'TBD'} ETB. Reason: {payment_reason}"
            if note:
                payment_note = f"{note}. {payment_note}"
            
            form.studentaffairs_note = payment_note
            form.save()

            payment_link = f"/student/payments?form_id={form.id}&department=studentaffairs"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if payment_reason:
                payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Student Affairs Payment Required",
                    message=f"❌ Form #{form.id} requires STUDENT AFFAIRS PAYMENT.\nAmount: {payment_amount or 'TBD'} ETB\nReason: {payment_reason}\nPay here: {payment_link}",
                    clearance_form=form
                )

            return Response({
                "message": "Payment required",
                "status": form.status,
                "payment_link": payment_link
            })
        else:
            form.status = "rejected"
            form.studentaffairs_note = f"Rejected by {request.user.get_full_name()} (Student Affairs): {note}"
            form.save()

            if form.student:
                Notification.objects.create(
                    user=form.student,
                    title="Form Rejected by Student Affairs",
                    message=f"❌ Your form #{form.id} has been REJECTED by Student Affairs.\nReason: {note}",
                    clearance_form=form
                )

            return Response({
                "message": "Form rejected",
                "status": form.status,
                "note": form.studentaffairs_note
            })

    return Response({"error": "Invalid action"}, status=400)

# Building CRUD endpoints

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def building_list(request):
    """Admin: List all buildings or create new one"""
    if request.method == 'GET':
        buildings = Building.objects.annotate(
            student_count=Count('building_students', distinct=True),
            staff_count=Count('assigned_staff', distinct=True),
            form_count=Count('form_buildings', distinct=True)
        ).order_by('name')
        
        data = []
        for building in buildings:
            data.append({
                'id': building.id,
                'name': building.name,
                'code': building.code,
                'address': building.address,
                'capacity': building.capacity,
                'is_active': building.is_active,
                'student_count': building.student_count,
                'staff_count': building.staff_count,
                'form_count': building.form_count,
                'created_at': building.created_at,
            })
        return Response(data)
    
    elif request.method == 'POST':
        serializer = BuildingSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Building created successfully",
                "data": serializer.data
            }, status=201)
        return Response(serializer.errors, status=400)

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def get_staff_with_buildings(request):
    """Get all dormitory staff with their assigned buildings"""
    try:
        staff_members = User.objects.filter(role='dormitory', is_active=True).prefetch_related('assigned_buildings')
        
        data = []
        for staff in staff_members:
            buildings = staff.assigned_buildings.all()
            data.append({
                'id': staff.id,
                'username': staff.username,
                'email': staff.email,
                'first_name': staff.first_name,
                'last_name': staff.last_name,
                'full_name': staff.get_full_name(),
                'is_active': not staff.is_blocked,
                'assigned_buildings': [
                    {
                        'id': b.id,
                        'name': b.name,
                        'code': b.code,
                        'capacity': b.capacity
                    } for b in buildings
                ],
                'building_count': buildings.count()
            })
        
        return Response(data)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def get_unassigned_dormitory_staff(request):
    """Get dormitory staff with no buildings assigned"""
    try:
        # Get staff with no assigned buildings
        staff_members = User.objects.filter(
            role='dormitory', 
            is_active=True
        ).annotate(
            building_count=Count('assigned_buildings')
        ).filter(building_count=0)
        
        data = []
        for staff in staff_members:
            data.append({
                'id': staff.id,
                'username': staff.username,
                'email': staff.email,
                'first_name': staff.first_name,
                'last_name': staff.last_name,
                'full_name': staff.get_full_name()
            })
        
        return Response(data)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def get_building_staff(request, building_id):
    """Get all staff assigned to a specific building"""
    try:
        building = Building.objects.get(id=building_id)
        staff_members = building.assigned_staff.filter(role='dormitory', is_active=True)
        
        data = []
        for staff in staff_members:
            data.append({
                'id': staff.id,
                'username': staff.username,
                'email': staff.email,
                'first_name': staff.first_name,
                'last_name': staff.last_name,
                'full_name': staff.get_full_name()
            })
        
        return Response({
            'building': {
                'id': building.id,
                'name': building.name,
                'code': building.code
            },
            'staff_count': len(data),
            'staff': data
        })
    except Building.DoesNotExist:
        return Response({"error": "Building not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def assign_dormitory_staff_buildings(request, staff_id):
    """Admin: Assign buildings to dormitory staff"""
    try:
        # Validate staff exists and is dormitory
        staff = User.objects.get(id=staff_id, role='dormitory')
    except User.DoesNotExist:
        return Response(
            {"error": f"Dormitory staff with ID {staff_id} not found"}, 
            status=404
        )
    
    # Get building IDs from request
    building_ids = request.data.get('building_ids', [])
    
    # Validate building_ids is a list
    if not isinstance(building_ids, list):
        return Response(
            {"error": "building_ids must be a list"}, 
            status=400
        )
    
    try:
        # If empty list, clear all assignments
        if not building_ids:
            staff.assigned_buildings.clear()
            return Response({
                "message": f"All buildings unassigned from {staff.username}",
                "staff_id": staff.id,
                "staff_name": staff.get_full_name() or staff.username,
                "assigned_buildings": []
            })
        
        # Validate buildings exist and are active
        buildings = Building.objects.filter(id__in=building_ids, is_active=True)
        
        # Check if all buildings were found
        if buildings.count() != len(building_ids):
            found_ids = set(buildings.values_list('id', flat=True))
            missing_ids = set(building_ids) - found_ids
            
            # Get details of missing buildings
            missing_buildings = Building.objects.filter(
                id__in=missing_ids
            ).values('id', 'name', 'is_active')
            
            missing_details = []
            for building in missing_buildings:
                status = "inactive" if not building['is_active'] else "not found"
                missing_details.append({
                    "id": building['id'],
                    "name": building['name'],
                    "status": status
                })
            
            return Response({
                "error": f"Some buildings not found or inactive",
                "missing_buildings": missing_details,
                "found_buildings": [
                    {"id": b.id, "name": b.name, "code": b.code}
                    for b in buildings
                ]
            }, status=400)
        
        # Assign buildings (this clears previous assignments and sets new ones)
        staff.assigned_buildings.set(buildings)
        
        # Get the assigned buildings with their details
        assigned_buildings_data = []
        for building in buildings:
            assigned_buildings_data.append({
                "id": building.id,
                "name": building.name,
                "code": building.code,
                "capacity": building.capacity,
                "student_count": building.building_students.filter(
                    is_active=True
                ).count()
            })
        
        return Response({
            "message": f"Assigned {buildings.count()} buildings to {staff.username}",
            "staff_id": staff.id,
            "staff_name": staff.get_full_name() or staff.username,
            "assigned_buildings": assigned_buildings_data
        })
        
    except Exception as e:
        return Response(
            {"error": f"Failed to assign buildings: {str(e)}"}, 
            status=500
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def bulk_assign_buildings(request):
    """Bulk assign buildings to multiple staff members"""
    try:
        assignments = request.data.get('assignments', [])
        
        if not assignments:
            return Response({"error": "No assignments provided"}, status=400)
        
        results = []
        for assignment in assignments:
            staff_id = assignment.get('staff_id')
            building_ids = assignment.get('building_ids', [])
            
            try:
                staff = User.objects.get(id=staff_id, role='dormitory')
                buildings = Building.objects.filter(id__in=building_ids, is_active=True)
                staff.assigned_buildings.set(buildings)
                
                results.append({
                    'staff_id': staff_id,
                    'staff_name': staff.get_full_name() or staff.username,
                    'status': 'success',
                    'assigned_count': buildings.count()
                })
            except User.DoesNotExist:
                results.append({
                    'staff_id': staff_id,
                    'status': 'failed',
                    'error': 'Staff not found'
                })
            except Exception as e:
                results.append({
                    'staff_id': staff_id,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return Response({
            'message': f'Processed {len(results)} assignments',
            'results': results
        })
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def building_detail(request, building_id):
    """Admin: Get, update or delete building"""
    try:
        building = Building.objects.annotate(
            student_count=Count('building_students', distinct=True),
            staff_count=Count('assigned_staff', distinct=True),
            form_count=Count('form_buildings', distinct=True)
        ).get(id=building_id)
    except Building.DoesNotExist:
        return Response({"error": "Building not found"}, status=404)
    
    if request.method == 'GET':
        data = {
            'id': building.id,
            'name': building.name,
            'code': building.code,
            'address': building.address,
            'capacity': building.capacity,
            'is_active': building.is_active,
            'student_count': building.student_count,
            'staff_count': building.staff_count,
            'form_count': building.form_count,
            'created_at': building.created_at,
        }
        return Response(data)
    
    elif request.method in ['PUT', 'PATCH']:
        serializer = BuildingSerializer(building, data=request.data, partial=(request.method == 'PATCH'))
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Building updated successfully",
                "data": serializer.data
            })
        return Response(serializer.errors, status=400)
    
    elif request.method == 'DELETE':
        # Check if building has students
        if building.building_students.filter(is_active=True).exists():
            return Response({
                "error": "Cannot delete building with assigned students"
            }, status=400)
        building.delete()
        return Response({"message": "Building deleted successfully"}, status=204)

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def assign_dormitory_staff_buildings(request, staff_id):
    """Admin: Assign buildings to dormitory staff"""
    try:
        staff = User.objects.get(id=staff_id, role='dormitory')
    except User.DoesNotExist:
        return Response({"error": "Dormitory staff not found"}, status=404)
    
    building_ids = request.data.get('building_ids', [])
    
    if not building_ids:
        return Response({"error": "No buildings provided"}, status=400)
    
    buildings = Building.objects.filter(id__in=building_ids, is_active=True)
    
    if buildings.count() != len(building_ids):
        return Response({"error": "Some buildings not found or inactive"}, status=400)
    
    staff.assigned_buildings.set(buildings)
    
    return Response({
        "message": f"Assigned {buildings.count()} buildings to {staff.username}",
        "assigned_buildings": [
            {"id": b.id, "name": b.name, "code": b.code} 
            for b in buildings
        ]
    })

# In your views.py - Add this view to get staff by building

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def get_staff_by_building(request, building_id):
    """Get all dormitory staff assigned to a specific building"""
    try:
        building = Building.objects.get(id=building_id)
        staff_members = building.assigned_staff.filter(role='dormitory', is_active=True)
        
        data = []
        for staff in staff_members:
            data.append({
                'id': staff.id,
                'username': staff.username,
                'email': staff.email,
                'full_name': staff.get_full_name(),
                'first_name': staff.first_name,
                'last_name': staff.last_name,
                'is_blocked': staff.is_blocked
            })
        
        return Response({
            'building': {
                'id': building.id,
                'name': building.name,
                'code': building.code
            },
            'staff_count': len(data),
            'staff': data
        })
        
    except Building.DoesNotExist:
        return Response({"error": "Building not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def export_building_stats(request):
    """Admin: Export building statistics to CSV"""
    buildings = Building.objects.annotate(
        student_count=Count('building_students', distinct=True),
        staff_count=Count('assigned_staff', distinct=True),
        form_count=Count('form_buildings', distinct=True)
    ).order_by('name')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="building_stats_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'Building Name', 'Building Code', 'Capacity', 'Current Students',
        'Assigned Staff', 'Pending Forms', 'Active Status', 'Address', 'Created Date'
    ])
    
    for building in buildings:
        writer.writerow([
            building.name,
            building.code,
            building.capacity or 'Unlimited',
            building.student_count,
            building.staff_count,
            building.form_buildings.filter(status='approved_studentaffairs').count(),
            'Active' if building.is_active else 'Inactive',
            building.address or 'N/A',
            building.created_at.strftime('%Y-%m-%d') if building.created_at else 'N/A'
        ])
    
    return response
# ==================== DORMITORY VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dormitory_forms(request):
    """
    Get clearance forms ONLY for students in the dormitory staff's assigned buildings
    Each dormitory manager sees ONLY their own building's students
    Forms must be approved by Student Affairs first
    """
    if request.user.role != "dormitory":
        return Response({"error": "Unauthorized - Dormitory access only"}, status=403)
    
    # Get buildings assigned to THIS SPECIFIC dormitory manager
    assigned_buildings = request.user.assigned_buildings.all()
    
    print(f"\n=== DORMITORY DASHBOARD ACCESS ===")
    print(f"Manager: {request.user.username} (ID: {request.user.id})")
    print(f"Name: {request.user.get_full_name()}")
    print(f"Assigned buildings: {[b.name for b in assigned_buildings]}")
    
    if not assigned_buildings.exists():
        print(f"WARNING: {request.user.username} has no buildings assigned")
        return Response({
            "staff_name": request.user.get_full_name() or request.user.username,
            "staff_id": request.user.id,
            "assigned_buildings": [],
            "forms": [],
            "total_forms": 0,
            "message": "No buildings assigned to you. Please contact admin."
        }, status=200)
    
    # CRITICAL: Get forms ONLY from students whose building is in THIS manager's assigned buildings
    # AND that are approved by Student Affairs
    forms = ClearanceForm.objects.filter(
        status="approved_studentaffairs",  # Must come from Student Affairs
        student_building__in=assigned_buildings  # This ensures ONLY this manager's students
    ).select_related('student', 'student_building').order_by('-created_at')
    
    print(f"Found {forms.count()} forms for {request.user.username}'s buildings from Student Affairs")
    
    # Format response - SIMPLE like department head
    response_data = []
    for form in forms:
        response_data.append({
            "id": form.id,
            "student_id": form.student.id if form.student else None,
            "student_email": form.student.email if form.student else None,
            "full_name": form.full_name,
            "id_number": form.id_number,
            "department_name": form.department_name,
            "college": form.college,
            "program_level": form.program_level,
            "enrollment_type": form.enrollment_type,
            "year": form.year,
            "semester": form.semester,
            "section": form.section,
            "reason": form.reason,
            "status": form.status,
            "building": {
                "id": form.student_building.id if form.student_building else None,
                "name": form.student_building.name if form.student_building else None,
                "code": form.student_building.code if form.student_building else None
            },
            "library_note": form.library_note or "",
            "cafeteria_note": form.cafeteria_note or "",
            "psychology_note": form.psychology_note or "",
            "sportmaster_note": form.sportmaster_note or "",
            "campuspolice_note": form.campuspolice_note or "",
            "cooperationsharing_note": form.cooperationsharing_note or "",
           # FIXED: Changed from dopcordinator_note to dopcoordinator_note
            "dopcoordinator_note": form.dopcoordinator_note or "",
            "studentaffairs_note": form.studentaffairs_note or "",
            "dormitory_note": form.dormitory_note or "",
            "created_at": form.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        })
    
    # Add assigned buildings info
    buildings_data = []
    for building in assigned_buildings:
        buildings_data.append({
            "id": building.id,
            "name": building.name,
            "code": building.code,
            "student_count": User.objects.filter(role='student', building=building, is_active=True).count()
        })
    
    print(f"✓ Returning {len(response_data)} forms to {request.user.username}")
    print(f"  Buildings: {[b['name'] for b in buildings_data]}")
    
    return Response({
        "staff_name": request.user.get_full_name() or request.user.username,
        "staff_id": request.user.id,
        "assigned_buildings": buildings_data,
        "forms": response_data,
        "total_forms": len(response_data)
    })



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def check_dorm_dues_api(request, student_id):
    """API endpoint to check dormitory dues"""
    if request.user.role not in ["dormitory", "admin"]:
        return Response({"error": "Unauthorized"}, status=403)

    try:
        # Find student by ID or ID number
        student = None
        
        # Try by numeric ID
        if student_id.isdigit():
            try:
                student = User.objects.get(id=int(student_id), role="student")
            except User.DoesNotExist:
                pass
        
        # If not found by ID, try by ID number
        if not student:
            try:
                student = User.objects.get(id_number=student_id, role="student")
            except User.DoesNotExist:
                pass
        
        if not student:
            return Response({"error": "Student not found"}, status=404)

        # Check dorm dues using helper function
        dorm_dues = check_student_dorm_dues(student_id)
        
        if not dorm_dues:
            return Response({"error": "Could not check dormitory dues"}, status=500)
        
        # Add student info to response
        dorm_dues.update({
            "student_id": student.id,
            "student_name": student.get_full_name() or student.username,
            "id_number": student.id_number if hasattr(student, 'id_number') else student_id,
            "email": student.email
        })
        
        return Response(dorm_dues)

    except Exception as e:
        print(f"Error checking dorm dues API: {e}")
        return Response({"error": str(e)}, status=500)

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def dormitory_action(request, pk):
    """
    Dormitory action - ONLY for students in the manager's assigned buildings
    After approval, sends to Registrar
    Like Department Head - can only act on their own students
    """
    if request.user.role != "dormitory":
        return Response({"error": "Unauthorized - Dormitory access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)
    
    print(f"\n=== DORMITORY ACTION ===")
    print(f"Manager: {request.user.username}")
    print(f"Form ID: {pk}")
    print(f"Student: {form.full_name}")
    print(f"Student Building: {form.student_building.name if form.student_building else 'None'}")
    
    # CRITICAL: Verify this student belongs to this manager's buildings
    assigned_buildings = request.user.assigned_buildings.all()
    
    if not form.student_building:
        return Response({
            "error": "Student has no building assigned",
            "message": "Cannot process this form"
        }, status=400)
    
    if form.student_building not in assigned_buildings:
        print(f"ERROR: {request.user.username} tried to access student from {form.student_building.name}")
        return Response({
            "error": f"You are not authorized to manage students from {form.student_building.name}",
            "message": f"You only manage: {[b.name for b in assigned_buildings]}",
            "your_buildings": [b.name for b in assigned_buildings]
        }, status=403)
    
    # Must be approved by Student Affairs first
    if form.status != "approved_studentaffairs":
        return Response({
            "error": f"Form must be approved by Student Affairs first. Current status: {form.status}"
        }, status=400)
        
    action = request.data.get("action")
    note = request.data.get("note", "")
    requires_payment = request.data.get("requires_payment", False)
    payment_amount = request.data.get("payment_amount")
    payment_reason = request.data.get("payment_reason", "")

    # ===== APPROVE =====
    if action == "approve":
        form.dormitory_approved_by = f"{request.user.get_full_name()} (Dormitory Manager - {form.student_building.name})"
        form.dormitory_approved_at = timezone.now()
        form.status = "approved_dormitory"  # Send to Registrar
        form.dormitory_note = note or f"Approved for {form.student_building.name} - Room clearance verified"

        form.save()
        
        print(f"✓ Form {pk} approved by {request.user.username}")
        print(f"  New status: {form.status} (sent to Registrar)")

        # Notify student
        if form.student:
            Notification.objects.create(
                user=form.student,
                title="✅ Form Approved by Dormitory",
                message=(
                    f"Your clearance form has been APPROVED by Dormitory Manager for {form.student_building.name}\n"
                    f"and sent to Registrar for final clearance.\n"
                    f"Note: {form.dormitory_note}"
                ),
                clearance_form=form,
                notification_type="success"
            )
            print(f"✓ Notification sent to student {form.student.username}")
        
        # Notify ALL Registrar staff
        registrar_users = User.objects.filter(role='registrar', is_active=True)
        notification_count = 0
        for registrar in registrar_users:
            Notification.objects.create(
                user=registrar,
                title="📋 New Form Ready for Registrar",
                message=(
                    f"Form #{form.id} from {form.full_name} ({form.student_building.name}) "
                    f"has been approved by Dormitory and is ready for final clearance.\n"
                    f"Student ID: {form.id_number}\n"
                    f"Department: {form.department_name}"
                ),
                clearance_form=form,
                notification_type="info"
            )
            notification_count += 1
        print(f"✓ Notified {notification_count} registrar(s) about form #{form.id}")
        
        return Response({
            "message": f"Form approved for {form.student_building.name} and sent to Registrar",
            "status": form.status,
            "approved_by": form.dormitory_approved_by,
            "approved_at": form.dormitory_approved_at,
            "next_department": "registrar",
            "building": {
                "id": form.student_building.id,
                "name": form.student_building.name,
                "code": form.student_building.code
            }
        })

    # ===== REJECT WITH PAYMENT =====
    elif action == "reject" and requires_payment:
        form.status = "requires_dormitory_payment"
        payment_note = f"Payment required for {form.student_building.name}: {payment_amount} ETB. Reason: {payment_reason}"
        if note:
            payment_note = f"{note}. {payment_note}"
        
        form.dormitory_note = payment_note
        form.save()
        
        print(f"⚠ Form {pk} requires payment. New status: {form.status}")

        payment_link = f"/student/payments?form_id={form.id}&department=dormitory"
        if payment_amount:
            payment_link += f"&amount={payment_amount}"
        if payment_reason:
            payment_link += f"&reason={payment_reason.replace(' ', '%20')}"

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="💰 Dormitory Payment Required",
                message=(
                    f"Your clearance form requires payment for {form.student_building.name}\n"
                    f"Amount: {payment_amount} ETB\n"
                    f"Reason: {payment_reason}\n"
                    f"Pay here: {payment_link}"
                ),
                clearance_form=form,
                notification_type="warning"
            )

        return Response({
            "message": "Payment required",
            "status": form.status,
            "payment_link": payment_link,
            "amount": payment_amount,
            "reason": payment_reason,
            "building": {
                "id": form.student_building.id,
                "name": form.student_building.name
            }
        })

    # ===== HARD REJECT =====
    elif action == "reject":
        form.status = "rejected"
        form.dormitory_note = f"Rejected by {request.user.get_full_name()} ({form.student_building.name}): {note}"
        form.save()
        
        print(f"✗ Form {pk} rejected")

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="❌ Form Rejected by Dormitory",
                message=(
                    f"Your clearance form has been REJECTED by Dormitory Manager for {form.student_building.name}\n"
                    f"Reason: {note}"
                ),
                clearance_form=form,
                notification_type="error"
            )

        return Response({
            "message": "Form rejected",
            "status": form.status,
            "note": form.dormitory_note
        })

    return Response(
        {"error": "Invalid action. Use 'approve' or 'reject'"},
        status=400
    )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def debug_dormitory_dashboard(request):
    """Debug endpoint - shows exactly what each dormitory manager sees"""
    if request.user.role != 'dormitory' and request.user.role != 'admin':
        return Response({"error": "Unauthorized"}, status=403)
    
    staff = request.user
    assigned_buildings = staff.assigned_buildings.all()
    
    debug_info = {
        "manager": {
            "id": staff.id,
            "username": staff.username,
            "full_name": staff.get_full_name(),
            "email": staff.email
        },
        "assigned_buildings": [],
        "students_you_manage": [],
        "forms_from_student_affairs": []  # Forms waiting for dormitory approval
    }
    
    # For each assigned building
    for building in assigned_buildings:
        # Students in this building
        students = User.objects.filter(
            role='student',
            building=building,
            is_active=True
        ).select_related('building')
        
        student_list = []
        for student in students:
            student_list.append({
                "id": student.id,
                "name": student.get_full_name(),
                "username": student.username,
                "id_number": student.id_number,
                "email": student.email
            })
        
        # Forms from this building that are approved by Student Affairs
        forms = ClearanceForm.objects.filter(
            student_building=building,
            status="approved_studentaffairs"  # Only forms from Student Affairs
        ).select_related('student')
        
        form_list = []
        for form in forms:
            form_list.append({
                "id": form.id,
                "student": form.full_name,
                "id_number": form.id_number,
                "status": form.status,
                "created_at": form.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        debug_info["assigned_buildings"].append({
            "id": building.id,
            "name": building.name,
            "code": building.code,
            "total_students": len(student_list),
            "pending_forms_from_student_affairs": len(form_list),
            "sample_students": student_list[:3]  # First 3 as sample
        })
        
        debug_info["students_you_manage"].extend(student_list)
        debug_info["forms_from_student_affairs"].extend(form_list)
    
    # If no buildings assigned
    if not assigned_buildings.exists():
        debug_info["message"] = "⚠️ No buildings assigned! Contact admin."
    
    return Response(debug_info)

# ==================== GET ALL FORMS (Public endpoint for registrar) ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_all_forms(request):
    """Get all forms for registrar"""
    if request.user.role != "registrar":
        return Response({"error": "Unauthorized - Registrar access only"}, status=403)
    
    forms = ClearanceForm.objects.all().order_by("-created_at")
    # Format the response
    formatted_forms = []
    for form in forms:
        # Check if all required departments have approved
        has_department_approval = form.note and ('Approved' in form.note or 'approved' in form.note)
        has_library_approval = form.library_note and ('Approved' in form.library_note or 'approved' in form.library_note)
        has_cafeteria_approval = form.cafeteria_note and ('Approved' in form.cafeteria_note or 'approved' in form.cafeteria_note)
        has_dormitory_approval = form.dormitory_note and ('Approved' in form.dormitory_note or 'approved' in form.dormitory_note)
        # Determine if ready for registrar
        is_ready_for_registrar = (
            has_department_approval and 
            has_library_approval and 
            has_cafeteria_approval and 
            has_dormitory_approval
        )
        
        formatted_forms.append({
            "id": form.id,
            "student": form.student.id if form.student else None,
            "student_id": form.student.id if form.student else None,
            "full_name": form.full_name,
            "id_number": form.id_number,
            "college": form.college,
            "department_name": form.department_name,
            "program_level": form.program_level,
            "enrollment_type": form.enrollment_type,
            "year": form.year,
            "semester": form.semester,
            "section": form.section,
            "reason": form.reason,
            "status": form.status,
            "note": form.note if hasattr(form, 'note') else "",
            "library_note": form.library_note if hasattr(form, 'library_note') else "",
            "cafeteria_note": form.cafeteria_note if hasattr(form, 'cafeteria_note') else "",
            "dormitory_note": form.dormitory_note if hasattr(form, 'dormitory_note') else "",
            "registrar_note": form.registrar_note if hasattr(form, 'registrar_note') else "",
            "created_at": form.created_at,
            "cleared_at": form.cleared_at if hasattr(form, 'cleared_at') else None,
            "has_all_approvals": is_ready_for_registrar,
            "approval_status": {
                "department": has_department_approval,
                "library": has_library_approval,
                "cafeteria": has_cafeteria_approval,
                "dormitory": has_dormitory_approval
            }
        })


def log_status(form, status, user, note=None):
    from .models import ClearanceFormStatusHistory
    ClearanceFormStatusHistory.objects.create(
        form=form,
        status=status,
        note=note,
        changed_by=user
    )

# ==================== HELPER FUNCTION ====================
def check_if_approved(note):
    """Check if a note indicates approval"""
    if not note:
        return False
    note_lower = note.lower()
    approved_keywords = ['approved', 'approve', 'clear', 'completed', 'no issues', 'no dues', 'sent to']
    return any(keyword in note_lower for keyword in approved_keywords)

# ==================== REGISTRAR VIEWS ====================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def registrar_forms(request):
    if request.user.role != "registrar":
        return Response(
            {"error": "Unauthorized - Registrar access only"},
            status=403
        )

    # Get forms that have all required approvals
    forms = ClearanceForm.objects.all().order_by("-created_at")
    valid_forms = []

    for form in forms:
        # Check if form has all required approvals based on status
        has_department = form.status in ["approved_department", "approved_library", "approved_cafeteria", "approved_dormitory", "completed"]
        has_library = form.status in ["approved_library", "approved_cafeteria", "approved_dormitory", "completed"]
        has_cafeteria = form.status in ["approved_cafeteria", "approved_dormitory", "completed"]
        has_dormitory = form.status in ["approved_dormitory", "completed"]
        
        # Check if form is NOT already cleared by registrar
        is_already_cleared = form.status == "Cleared by Registrar"

        # Registrar sees forms that have reached dormitory approval AND not already cleared
        if has_dormitory and not is_already_cleared:
            valid_forms.append({
                "id": form.id,
                "student_id": form.student.id if form.student else None,
                "full_name": form.full_name,
                "id_number": form.id_number,
                "college": form.college,
                "department_name": form.department_name,
                "program_level": form.program_level,
                "enrollment_type": form.enrollment_type,
                "year": form.year,
                "semester": form.semester,
                "section": form.section,
                "reason": form.reason,
                "status": form.status,
                "created_at": form.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "has_all_approvals": True,
                "approval_status": {
                    "department": has_department,
                    "library": has_library,
                    "cafeteria": has_cafeteria,
                    "dormitory": has_dormitory
                }
            })

    return Response(valid_forms)



@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def registrar_action(request, pk):
    if request.user.role != "registrar":
        return Response(
            {"error": "Unauthorized - Registrar access only"},
            status=403
        )

    form = get_object_or_404(ClearanceForm, pk=pk)

    # Must be approved by Dormitory first
    if form.status != "approved_dormitory":
        return Response({
            "error": "Cannot process. Form must be approved by Dormitory first.",
            "current_status": form.status
        }, status=400)

    action = request.data.get("action")
    note = request.data.get("note", "")

    # ================= APPROVE =================
    if action == "approve":
        form.registrar_approved_by = (
            f"{request.user.get_full_name()} (University Registrar)"
        )
        form.registrar_approved_at = timezone.now()
        form.cleared_at = timezone.now()
        form.status = "Cleared by Registrar"

        form.registrar_note = "Final approval granted"
        if note:
            form.registrar_note += f": {note}"

        form.save()

        # Notify student
        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Clearance Completed 🎓",
                message=(
                    "🎉 Congratulations! Your clearance form has been "
                    "fully approved and CLEARED by the Registrar.\n"
                    "You can now download your clearance certificate."
                ),
                clearance_form=form
            )
            

            certificate_id = f"CLEAR-{form.id_number}-{timezone.now().strftime('%Y%m%d')}"

            ClearanceCertificate.objects.get_or_create(
             clearance_form=form,
               defaults={"certificate_id": certificate_id}
                        )

        # Optional email notification
        if form.student and form.student.email:
            try:
                send_mail(
                    subject="University Clearance Approved",
                    message=(
                        f"Dear {form.full_name},\n\n"
                        "Your clearance process has been completed successfully.\n"
                        "You may now download your clearance certificate.\n\n"
                        "University Registrar"
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[form.student.email],
                    fail_silently=True,
                )
            except Exception as e:
                print(f"Email sending error: {e}")

        return Response({
            "message": "Form cleared successfully",
            "status": form.status,
            "cleared_at": form.cleared_at,
            "approved_by": form.registrar_approved_by
        })

    # ================= REJECT =================
    elif action == "reject":
        form.status = "rejected"
        form.registrar_note = (
            f"Rejected by {request.user.get_full_name()} (Registrar)"
        )
        if note:
            form.registrar_note += f": {note}"

        form.save()

        if form.student:
            Notification.objects.create(
                user=form.student,
                title="Clearance Rejected by Registrar",
                message=(
                    f"❌ Your clearance form has been REJECTED by the Registrar.\n"
                    f"Reason: {note}"
                ),
                clearance_form=form
            )

        return Response({
            "message": "Form rejected by Registrar",
            "status": form.status,
            "note": form.registrar_note
        })

    # ================= INVALID ACTION =================
    return Response(
        {"error": "Invalid action. Use 'approve' or 'reject'"},
        status=400
    )

@api_view(["GET"])
@permission_classes([])  # Public
def verify_certificate(request, certificate_id):
    try:
        cert = ClearanceCertificate.objects.select_related(
            "clearance_form"
        ).get(certificate_id=certificate_id, is_valid=True)

        form = cert.clearance_form

        return Response({
            "valid": True,
            "certificate_id": cert.certificate_id,
            "issued_at": cert.issued_at,
            "student": {
                "full_name": form.full_name,
                "id_number": form.id_number,
                "college": form.college,
                "department": form.department_name,
                "program": form.program_level,
                "year": form.year,
                "semester": form.semester,
            },
            "approvals": {
                "department_head": form.department_approved_by,
                "library": form.library_approved_by,
                "cafeteria": form.cafeteria_approved_by,
                "dormitory": form.dormitory_approved_by,
                "registrar": form.registrar_approved_by,
            },
            "status": form.status,
        })

    except ClearanceCertificate.DoesNotExist:
        return Response({
            "valid": False,
            "message": "Invalid or revoked certificate"
        }, status=404)



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def registrar_statistics(request):
    if request.user.role != "registrar":
        return Response({"error": "Unauthorized - Registrar access only"}, status=403)

    all_forms = ClearanceForm.objects.all()
    
    total = all_forms.count()
    cleared = all_forms.filter(status="Cleared by Registrar").count()
    
    # Count pending forms (approved by dormitory but not cleared by registrar)
    pending = all_forms.filter(status="approved_dormitory").count()
    
    # Count waiting forms (not yet reached dormitory)
    waiting = all_forms.exclude(status__in=["approved_dormitory", "Cleared by Registrar", "rejected"]).count()
    
    # Get department-wise statistics
    department_stats = []
    for dept in Department.objects.all():
        dept_forms = all_forms.filter(department_name=dept.name)
        dept_total = dept_forms.count()
        dept_cleared = dept_forms.filter(status="Cleared by Registrar").count()
        dept_pending = dept_forms.filter(status="approved_dormitory").count()
        
        if dept_total > 0:
            department_stats.append({
                "department": dept.name,
                "total": dept_total,
                "cleared": dept_cleared,
                "pending": dept_pending,
                "completion_rate": round((dept_cleared / dept_total) * 100, 2) if dept_total > 0 else 0
            })
    
    return Response({
        "total": total,
        "cleared": cleared,
        "pending": pending,
        "waiting": waiting,
        "completion_rate": round((cleared / total) * 100, 2) if total > 0 else 0,
        "department_stats": department_stats,
        "daily_cleared": all_forms.filter(
            cleared_at__date=timezone.now().date(),
            status="Cleared by Registrar"
        ).count(),
        "monthly_cleared": all_forms.filter(
            cleared_at__month=timezone.now().month,
            cleared_at__year=timezone.now().year,
            status="Cleared by Registrar"
        ).count(),
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def generate_clearance_certificate(request, pk):
    if request.user.role != "registrar":
        return Response({"error": "Registrar access only"}, status=403)

    form = get_object_or_404(ClearanceForm, pk=pk)

    if form.status != "Cleared by Registrar":
        return Response({"error": "Form not cleared by registrar"}, status=400)

    certificate_data = {
        "student_name": form.full_name,
        "id_number": form.id_number,
        "college": form.college,
        "department": form.department_name,
        "program_level": form.program_level,
        "year": form.year,
        "semester": form.semester,
        "status": form.status,
        "approvals": {
            "department": {
                "status": "Approved" if form.status != "pending_department" else "Pending",
                "approved_by": form.department_approved_by,
                "date": form.department_approved_at.strftime('%Y-%m-%d') if form.department_approved_at else None,
                "note": form.department_note,
            },
            "library": {
                "status": "Approved" if form.status in [
                    "approved_library",
                    "approved_cafeteria",
                    "approved_dormitory",
                    "Cleared by Registrar"
                ] else "Pending",
                "approved_by": form.library_approved_by,
                "date": form.library_approved_at.strftime('%Y-%m-%d') if form.library_approved_at else None,
                "note": form.library_note,
            },
            "cafeteria": {
                "status": "Approved" if form.status in [
                    "approved_cafeteria",
                    "approved_dormitory",
                    "Cleared by Registrar"
                ] else "Pending",
                "approved_by": form.cafeteria_approved_by,
                "date": form.cafeteria_approved_at.strftime('%Y-%m-%d') if form.cafeteria_approved_at else None,
                "note": form.cafeteria_note,
            },
            "dormitory": {
                "status": "Approved" if form.status in [
                    "approved_dormitory",
                    "Cleared by Registrar"
                ] else "Pending",
                "approved_by": form.dormitory_approved_by,
                "date": form.dormitory_approved_at.strftime('%Y-%m-%d') if form.dormitory_approved_at else None,
                "note": form.dormitory_note,
            },
            "registrar": {
                "status": "Final Approval",
                "approved_by": form.registrar_approved_by,
                "date": form.registrar_approved_at.strftime('%Y-%m-%d') if form.registrar_approved_at else None,
                "note": form.registrar_note,
            },
        },
        "certificate_id": f"CLEAR-{form.id_number}-{timezone.now().strftime('%Y%m%d')}",
        "generated_at": timezone.now().isoformat(),
    }

    return Response(certificate_data)

@api_view(['GET'])
@permission_classes([AllowAny])
def api_view_endpoint(request):
    """Simple test endpoint for the React app"""
    return Response({
        "message": "API is working!",
        "status": "success",
        "timestamp": timezone.now().isoformat()
    })

# ==================== CLEARANCE FORM REQUESTS (Admin) ====================
class ClearanceFormRequestsListView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]

    def get(self, request):
        forms = ClearanceForm.objects.all().order_by("-id")
        return Response([{
            "id": f.id,
            "student_name": f.full_name,
            "student_email": f.student.email if f.student else "N/A",
            "department": f.department_name,
            "status": f.status,
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for f in forms])

@api_view(["PATCH"])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def update_form_request(request, pk):
    form = get_object_or_404(ClearanceForm, pk=pk)
    new_status = request.data.get("status")
    
    if new_status not in [choice[0] for choice in ClearanceForm.STATUS_CHOICES]:
        return Response({"error": "Invalid status"}, status=400)
    
    form.status = new_status
    form.save()
    return Response({"message": "Status updated", "form": ClearanceFormSerializer(form).data})

# ==================== COLLEGE & DEPARTMENT CRUD VIEWS (Admin only) ====================
class CollegeListCreateView(generics.ListCreateAPIView):
    queryset = College.objects.all().order_by('name')
    serializer_class = CollegeSerializer
    permission_classes = [IsAuthenticated, IsAdminUserRole]

class CollegeDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = College.objects.all()
    serializer_class = CollegeSerializer
    permission_classes = [IsAuthenticated, IsAdminUserRole]

class DepartmentListCreateView(generics.ListCreateAPIView):
    queryset = Department.objects.all().order_by('name')
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated, IsAdminUserRole]

class DepartmentDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated, IsAdminUserRole]

# ==================== PUBLIC VIEWS ====================
@api_view(["GET"])
@permission_classes([AllowAny])
def public_colleges_list(request):
    """Public endpoint for colleges"""
    colleges = College.objects.all()
    serializer = CollegeSerializer(colleges, many=True)
    return Response(serializer.data)

@api_view(["GET"])
@permission_classes([AllowAny])
def public_departments_list(request):
    """Public endpoint for departments"""
    departments = Department.objects.all()
    serializer = DepartmentSerializer(departments, many=True)
    return Response(serializer.data)

# ==================== PASSWORD RESET ENDPOINTS ====================
@api_view(['POST'])
@permission_classes([AllowAny])
def send_reset_otp(request):
    """Send OTP for password reset"""
    try:
        logger.info(f"Received password reset request with data: {request.data}")
        email = request.data.get('email')
        
        if not email:
            logger.error("No email provided in request")
            return Response({"error": "Email is required"}, status=400)
        
        logger.info(f"Looking for user with email: {email}")
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
            logger.info(f"User found: {user.username}")
        except User.DoesNotExist:
            logger.error(f"User with email {email} not found")
            return Response({"error": "User with this email does not exist"}, status=404)
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        logger.info(f"Generated OTP for {email}: {otp}")
        
        # Delete any existing OTP for this email
        deleted_count = PasswordResetOTP.objects.filter(email=email).delete()
        logger.info(f"Deleted {deleted_count} existing OTPs for {email}")
        
        # Save OTP with expiration (15 minutes)
        expires_at = timezone.now() + timedelta(minutes=15)
        otp_obj = PasswordResetOTP.objects.create(
            email=email,
            otp=otp,
            expires_at=expires_at
        )
        logger.info(f"Created OTP object with ID: {otp_obj.id}")
        
        # Send email (in production)
        try:
            logger.info(f"Attempting to send email to {email}")
            send_mail(
                subject='Password Reset OTP',
                message=f'Your OTP for password reset is: {otp}. This OTP is valid for 15 minutes.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False

            )
            logger.info("Email sent successfully")
        except Exception as e:
            logger.error(f"Email sending error: {e}")
            # Continue anyway for development
        
        return Response({
            "message": "OTP sent successfully",
            "email": email,
            "expires_in": "15 minutes"
        }, status=200)
        
    except Exception as e:
        logger.exception(f"Unhandled exception in send_reset_otp: {str(e)}")
        return Response({"error": "Internal server error. Please try again later."}, status=500)
@api_view(['GET'])
@permission_classes([AllowAny])
def test_password_reset(request):
    """Test endpoint for password reset system"""
    try:
        # Check if settings are configured
        email_backend = getattr(settings, 'EMAIL_BACKEND', 'Not set')
        email_host = getattr(settings, 'EMAIL_HOST', 'Not set')
        
        # Check if models are accessible
        user_count = User.objects.count()
        otp_count = PasswordResetOTP.objects.count()
        
        # Check database connection
        from django.db import connection
        connection.ensure_connection()
        
        return Response({
            "status": "OK",
            "email_backend": email_backend,
            "email_host": email_host,
            "total_users": user_count,
            "total_otps": otp_count,
            "database": "Connected"
        }, status=200)
        
    except Exception as e:
        return Response({
            "status": "ERROR",
            "error": str(e),
            "type": type(e).__name__
        }, status=500)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_reset_otp(request):
    """Verify OTP for password reset"""
    try:
        email = request.data.get('email')
        otp = request.data.get('otp')
        
        if not email or not otp:
            return Response({"error": "Email and OTP are required"}, status=400)
        
        # Find the most recent valid OTP
        otp_obj = PasswordResetOTP.objects.filter(
            email=email,
            otp=otp,
            is_used=False,
            expires_at__gt=timezone.now()
        ).order_by('-created_at').first()
        
        if not otp_obj:
            return Response({"error": "Invalid or expired OTP"}, status=400)
        
        # Mark OTP as used
        otp_obj.is_used = True
        otp_obj.save()
        
        # Generate verification token
        verification_token = str(random.randint(100000, 999999))
        otp_obj.verification_token = verification_token
        otp_obj.save()
        
        return Response({
            "message": "OTP verified successfully",
            "verification_token": verification_token,
            "email": email
        }, status=200)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    """Reset password with verification token"""
    try:
        email = request.data.get('email')
        verification_token = request.data.get('verification_token')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        # Validate inputs
        if not all([email, verification_token, new_password, confirm_password]):
            return Response({"error": "All fields are required"}, status=400)
        
        if new_password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=400)
        
        if len(new_password) < 6:
            return Response({"error": "Password must be at least 6 characters"}, status=400)
        
        # Verify the token
        otp_obj = PasswordResetOTP.objects.filter(
            email=email,
            verification_token=verification_token,
            is_used=True
        ).order_by('-created_at').first()
        
        if not otp_obj:
            return Response({"error": "Invalid verification token"}, status=400)
        
        # Check if token is still valid (30 minutes)
        if otp_obj.created_at < timezone.now() - timedelta(minutes=30):
            return Response({"error": "Verification token has expired"}, status=400)
        
        # Get user and update password
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
        
        # Update password
        user.set_password(new_password)
        user.save()
        
        # Mark token as used for password reset
        otp_obj.is_password_reset = True
        otp_obj.save()
        
        # Delete all OTPs for this email
        PasswordResetOTP.objects.filter(email=email).delete()
        
        # Send confirmation email
        try:
            send_mail(
                subject='Password Reset Successful',
                message=f'Your password has been successfully reset. If you did not initiate this, please contact support.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=True,
            )
        except Exception:
            pass
        
        return Response({
            "message": "Password reset successfully",
            "email": email
        }, status=200)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ==================== CHANGE PASSWORD (Authenticated Users) ====================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """Change password for authenticated users"""
    try:
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        # Validate inputs
        if not all([current_password, new_password, confirm_password]):
            return Response({"error": "All fields are required"}, status=400)
        
        if new_password != confirm_password:
            return Response({"error": "New passwords do not match"}, status=400)
        
        if len(new_password) < 6:
            return Response({"error": "Password must be at least 6 characters"}, status=400)
        
        # Verify current password
        if not user.check_password(current_password):
            return Response({"error": "Current password is incorrect"}, status=401)
        
        # Update password
        user.set_password(new_password)
        user.save()
        
        # Update token (optional - forces re-login)
        # request.auth.delete()
        
        return Response({
            "message": "Password changed successfully",
            "username": user.username
        }, status=200)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)

# ==================== DELETE FORM ====================
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_form(request, form_id):
    """Delete a form (only if not in processing)"""
    if request.user.role != 'student':
        return Response({"error": "Only students can delete their forms"}, status=403)
    
    try:
        form = ClearanceForm.objects.get(
            id=form_id,
            student=request.user
        )
        
        # Check if form can be deleted (only pending or rejected forms)
        if form.status not in ['pending_department', 'rejected', 'pending_resubmission']:
            return Response({
                "error": "Cannot delete form. It is already being processed."
            }, status=400)
        
        # Delete form
        form.delete()
        
        return Response({
            "message": "Form deleted successfully"
        })
        
    except ClearanceForm.DoesNotExist:
        return Response({"error": "Form not found"}, status=404)

# ==================== GET FORM WITH FAULTS ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_form_with_faults(request, form_id):
    """Get form details with all faults"""
    try:
        form = ClearanceForm.objects.get(id=form_id)
        
        # Check permissions
        if request.user.role == 'student' and form.student != request.user:
            return Response({"error": "Unauthorized"}, status=403)
        
        # Get form progress
        form_data = ClearanceFormSerializer(form).data
        
        # Add can_resubmit flag
        form_data['can_resubmit'] = form.status in ['rejected', 'pending_resubmission']
        
        return Response(form_data)
        
    except ClearanceForm.DoesNotExist:
        return Response({"error": "Form not found"}, status=404)

# ==================== GET STUDENT DASHBOARD DATA ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def student_dashboard_data(request):
    """Get all data needed for student dashboard"""
    if request.user.role != 'student':
        return Response({"error": "Unauthorized"}, status=403)
    
    # Get all forms
    forms = ClearanceForm.objects.filter(student=request.user).order_by('-created_at')
    
    # Get notifications
    notifications = Notification.objects.filter(
        user=request.user,
        is_read=False
    ).order_by('-created_at')[:10]
    
    # Prepare response
    response_data = {
        "forms": [],
        "notifications": [],
        "stats": {
            "total_forms": forms.count(),
            "approved_forms": forms.filter(status='Cleared by Registrar').count(),
            "pending_forms": forms.filter(status__in=['pending_department', 'approved_department', 'approved_library', 'approved_cafeteria', 'approved_dormitory']).count(),
            "rejected_forms": forms.filter(status='rejected').count(),
        }
    }
    
    # Add forms with their faults
    for form in forms:
        form_data = {
            "id": form.id,
            "full_name": form.full_name,
            "id_number": form.id_number,
            "department_name": form.department_name,
            "status": form.status,
            "created_at": form.created_at,
            "updated_at": form.updated_at,
            "can_resubmit": form.status in ['rejected', 'pending_resubmission'],
        }
        
        response_data["forms"].append(form_data)
    
    # Add notifications
    for notification in notifications:
        response_data["notifications"].append({
            "id": notification.id,
            "message": notification.message,
            "created_at": notification.created_at,
            "is_read": notification.is_read
        })
    
    return Response(response_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_clearance_certificate(request, form_id):
    try:
        form = ClearanceForm.objects.get(id=form_id)

        # Permission check
        if request.user.role == 'student' and form.student != request.user:
            return Response({"error": "Unauthorized"}, status=403)

        if form.status != "Cleared by Registrar":
            return Response({"error": "Form not cleared yet"}, status=400)

        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter

        # ================= BORDER =================
        p.setLineWidth(2)
        p.rect(40, 40, width - 80, height - 80)

        # ================= HEADER =================
        p.setFont("Helvetica-Bold", 26)
        p.drawCentredString(width / 2, height - 90, "MAU CLEARANCE CERTIFICATE")

        p.setFont("Helvetica", 12)
        p.drawCentredString(
            width / 2,
            height - 120,
            "This is to officially certify that the following student"
        )

        # ================= STUDENT NAME =================
        p.setFont("Helvetica-Bold", 18)
        p.drawCentredString(width / 2, height - 165, form.full_name.upper())

        # ================= STUDENT DETAILS =================
        y = height - 210
        p.setFont("Helvetica", 12)

        details = [
            ("ID Number", form.id_number),
            ("Department", form.department_name),
            ("College", form.college),
            ("Program", form.program_level),
            ("Academic Year / Semester", f"{form.year} / {form.semester}"),
        ]

        for label, value in details:
            p.drawString(120, y, f"{label}:")
            p.drawString(280, y, value)
            y -= 22

        # ================= APPROVALS =================
        y = y - 30
        p.setFont("Helvetica-Bold", 13)
        p.drawString(100, y, "Clearance Approvals")
        p.line(100, y - 3, width - 100, y - 3)

        y -= 30
        p.setFont("Helvetica", 11)

        approvals = [
            ("Department Head", form.department_approved_by),
            ("Library", form.library_approved_by),
            ("Cafeteria", form.cafeteria_approved_by),
            ("Psychology", form.psychology_approved_by),
            ("Sport Master", form.sportmaster_approved_by),
            ("Campus Police", form.campuspolice_approved_by),
            ("Cooperation Sharing", form.cooperationsharing_approved_by),
            ("DOP Coordinator", form.dopcoordinator_approved_by),
            ("Student Affairs", form.studentaffairs_approved_by),
            ("Dormitory", form.dormitory_approved_by),
            ("Registrar", form.registrar_approved_by),
        ]

        for role, name in approvals:
            if name:  # Only display if approved
                p.drawString(120, y, f"{role}:")
                # Handle long names by truncating if necessary
                display_name = name
                if len(display_name) > 40:
                    display_name = display_name[:37] + "..."
                p.drawString(280, y, display_name or "—")
                y -= 18
            
            # ================= CLEARANCE STATEMENT =================
        y = y - 20  # Add some spacing
        p.setFont("Helvetica", 12)
        p.drawCentredString(
            width / 2,
            y - 10,
            "has successfully fulfilled all clearance requirements and"
        )
        p.drawCentredString(
            width / 2,
            y - 25,
            "is hereby fully cleared from the University."
        )

        # ================= QR CODE =================
        certificate_id = f"CLEAR-{form.id_number}-{form.cleared_at.strftime('%Y%m%d') if form.cleared_at else timezone.now().strftime('%Y%m%d')}"

        qr_data = (
            f"Certificate ID: {certificate_id}\n"
            f"Name: {form.full_name}\n"
            f"ID: {form.id_number}\n"
            f"Department: {form.department_name}\n"
            f"Status: {form.status}\n"
            f"Issue Date: {form.cleared_at.strftime('%Y-%m-%d')}"
        )

        qr = qrcode.make(qr_data)
        qr_buffer = io.BytesIO()
        qr.save(qr_buffer, format="PNG")
        qr_buffer.seek(0)

        qr_image = ImageReader(qr_buffer)

        qr_size = 90
        p.drawImage(
            qr_image,
            width - qr_size - 90,
            120,
            width=qr_size,
            height=qr_size
        )

        p.setFont("Helvetica", 9)
        p.drawCentredString(
            width - qr_size / 2 - 90,
            105,
            "Scan to verify"
        )

        # ================= SIGNATURE =================
        p.line(120, 120, 320, 120)
        p.setFont("Helvetica", 11)
        p.drawCentredString(220, 100, "University Registrar")

        # ================= FOOTER =================
        p.setFont("Helvetica", 9)
        p.drawString(120, 80, f"Certificate ID: {certificate_id}")
        p.drawString(120, 65, f"Issue Date: {form.cleared_at.strftime('%Y-%m-%d')}")

        p.showPage()
        p.save()
        buffer.seek(0)

        response = HttpResponse(buffer, content_type="application/pdf")
        response["Content-Disposition"] = (
            f'attachment; filename="clearance_certificate_{form.id_number}.pdf"'
        )
        return response

    except ClearanceForm.DoesNotExist:
        return Response({"error": "Form not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ==================== FORM STATUS TRACKING ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_form_progress(request, form_id):
    """Get detailed progress of a form"""
    try:
        form = ClearanceForm.objects.get(id=form_id)
        
        # Check permissions
        if request.user.role == 'student' and form.student != request.user:
            return Response({"error": "Unauthorized"}, status=403)
        
        # Get form progress
        progress = {
            "form_id": form.id,
            "student_name": form.full_name,
            "id_number": form.id_number,
            "current_status": form.status,
            "created_at": form.created_at,
            "updated_at": form.updated_at,
            "stages": [
                {
                    "name": "Department Head",
                    "status": "completed" if form.note else "pending",
                    "note": form.note,
                    "date": form.created_at if form.note else None
                },
                {
                    "name": "Librarian",
                    "status": "completed" if form.library_note else "pending",
                    "note": form.library_note,
                    "date": form.updated_at if form.library_note else None
                },
                {
                    "name": "Cafeteria",
                    "status": "completed" if form.cafeteria_note else "pending",
                    "note": form.cafeteria_note,
                    "date": form.updated_at if form.cafeteria_note else None
                },
                {
                    "name": "Dormitory",
                    "status": "completed" if form.dormitory_note else "pending",
                    "note": form.dormitory_note,
                    "date": form.updated_at if form.dormitory_note else None
                },
                {
                    "name": "Registrar",
                    "status": "completed" if form.status == "Cleared by Registrar" else "pending",
                    "note": "Cleared by Registrar" if form.status == "Cleared by Registrar" else "",
                    "date": form.cleared_at if hasattr(form, 'cleared_at') and form.cleared_at else None
                }
            ],
            "is_complete": form.status == "Cleared by Registrar",
            "can_resubmit": form.status == "rejected"
        }
        
        return Response(progress)
        
    except ClearanceForm.DoesNotExist:
        return Response({"error": "Form not found"}, status=404)
    

# ==================== RESUBMIT FORM ====================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resubmit_form(request, original_form_id):
    if request.user.role != 'student':
        return Response({"error": "Only students can resubmit forms"}, status=403)

    try:
        original_form = ClearanceForm.objects.get(
            id=original_form_id,
            student=request.user,
            status__in=['rejected', 'pending_resubmission']
        )

        # Clone original form safely
        new_form = ClearanceForm.objects.create(
            student=original_form.student,
            full_name=original_form.full_name,
            id_number=original_form.id_number,
            academic_year=original_form.academic_year,
            program_level=original_form.program_level,
            enrollment_type=original_form.enrollment_type,
            college=original_form.college,  # FK safe
            department_name=original_form.department_name,
            section=original_form.section,
            last_attendance=original_form.last_attendance,
            year=original_form.year,
            semester=original_form.semester,
            reason=original_form.reason,

            # Reset workflow
            status="pending_department"
        )

        # Notify department head
        dept_head = User.objects.filter(
            role='departmenthead',
            department=original_form.department_name
        ).first()

        if dept_head:
            Notification.objects.create(
                user=dept_head,
                message=f"Resubmitted clearance form #{new_form.id} from student {request.user.username}",
                clearance_form=new_form
            )

        return Response({
            "message": "Form resubmitted successfully",
            "new_form_id": new_form.id,
            "status": new_form.status
        }, status=201)

    except ClearanceForm.DoesNotExist:
        return Response({"error": "Form not found or cannot be resubmitted"}, status=404)



def validate_image_file(file):
    """Validate image file"""
    try:
        # Check file size (max 5MB)
        if file.size > 5 * 1024 * 1024:
            return False, "File size must be less than 5MB"
        
        # Check file type
        allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
        if file.content_type not in allowed_types:
            return False, "Only JPEG, PNG, GIF, and WebP images are allowed"
        
        # Verify it's a valid image
        img = Image.open(file)
        img.verify()
        
        return True, "Valid image"
    except Exception as e:
        return False, f"Invalid image file: {str(e)}"

def handle_base64_profile_picture(request):
    """Handle base64 image data for profile picture"""
    try:
        user = request.user
        base64_data = request.data.get('profile_picture_base64')
        
        if not base64_data:
            return Response({"error": "No image data provided"}, status=400)
        
        # Check if it's a data URL
        if 'data:image' in base64_data:
            # Extract base64 part
            format, imgstr = base64_data.split(';base64,')
            ext = format.split('/')[-1]
        else:
            # Assume it's raw base64
            imgstr = base64_data
            ext = 'png'  # default extension
        
        # Decode base64
        data = base64.b64decode(imgstr)
        
        # Validate file size
        if len(data) > 5 * 1024 * 1024:
            return Response({"error": "Image size must be less than 5MB"}, status=400)
        
        # Create image from bytes
        img = Image.open(BytesIO(data))
        
        # Validate image
        img.verify()
        
        # Generate filename
        filename = f"profile_{user.id}_{int(timezone.now().timestamp())}.{ext}"
        
        # Delete old profile picture if exists
        if user.profile_picture:
            try:
                user.profile_picture.delete(save=False)
            except:
                pass
        
        # Save new profile picture
        user.profile_picture.save(
            filename,
            ContentFile(data),
            save=False
        )
        
        user.save()
        
        return Response({
            "message": "Profile picture uploaded successfully",
            "profile_picture_url": user.get_profile_picture_url()
        })
        
    except Exception as e:
        logger.error(f"Error handling base64 profile picture: {e}")
        return Response({"error": "Failed to process image"}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_complete_profile(request):
    """Get complete user profile with statistics"""
    try:
        user = request.user
        
        # Debug: Print authentication info
        print(f"Profile request for user: {user.username} (ID: {user.id}, Role: {user.role})")
        
        # Prepare user data
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "role": user.role,
            "phone": user.phone or "",
            "department": user.department.name if user.department else None,
            "department_name": user.department.name if user.department else None,
            "department_id": user.department.id if user.department else None,
            "profile_picture_url": user.get_profile_picture_url(),
            "is_blocked": user.is_blocked,
            "is_active": user.is_active,
            "date_joined": user.date_joined,
            "last_login": user.last_login,
            "last_password_change": getattr(user, 'last_password_change', None),
        }
        
        # Calculate profile completion
        total_fields = 6
        completed_fields = 0
        if user.username: completed_fields += 1
        if user.email: completed_fields += 1
        if user.first_name: completed_fields += 1
        if user.last_name: completed_fields += 1
        if user.phone: completed_fields += 1
        if user.profile_picture: completed_fields += 1
        profile_completion = round((completed_fields / total_fields) * 100) if total_fields > 0 else 0
        
        # Get user statistics based on role
        stats = {}
        recent_activities = []
        
        if user.role == 'student':
            # Student stats
            forms = ClearanceForm.objects.filter(student=user)
            stats = {
                "total_forms": forms.count(),
                "approved_forms": forms.filter(status="Cleared by Registrar").count(),
                "pending_forms": forms.filter(status__in=['pending_department', 'approved_department', 'approved_library', 'approved_cafeteria', 'approved_dormitory']).count(),
                "rejected_forms": forms.filter(status='rejected').count(),
            }
            
            # Recent forms
            recent_forms = forms.order_by('-created_at')[:3]
            recent_activities = [{
                "type": "form",
                "id": f.id,
                "title": f"Form #{f.id}",
                "description": f.status,
                "date": f.created_at,
                "status": f.status
            } for f in recent_forms]
        
        elif user.role == 'departmenthead':
            # Department head stats
            if user.department:
                dept_forms = ClearanceForm.objects.filter(department_name=user.department.name)
                stats = {
                    "total_forms": dept_forms.count(),
                    "pending_forms": dept_forms.filter(status="pending_department").count(),
                    "approved_forms": dept_forms.filter(status="approved_department").count(),
                    "rejected_forms": dept_forms.filter(status="rejected").count(),
                }
        
        elif user.role in ['librarian', 'cafeteria', 'dormitory']:
            # Staff stats
            department_map = {
                'librarian': 'library',
                'cafeteria': 'cafeteria',
                'dormitory': 'dormitory'
            }
            dept_type = department_map.get(user.role)
            if dept_type:
                payments = StudentPayment.objects.filter(department_type=dept_type)
                stats = {
                    "total_payments": payments.count(),
                    "pending_payments": payments.filter(status="pending").count(),
                    "verified_payments": payments.filter(status="verified").count(),
                    "rejected_payments": payments.filter(status="rejected").count(),
                }
        
        elif user.role == 'registrar':
            # Registrar stats
            forms = ClearanceForm.objects.all()
            stats = {
                "total_forms": forms.count(),
                "cleared_forms": forms.filter(status="Cleared by Registrar").count(),
                "pending_forms": forms.filter(status="approved_dormitory").count(),
            }
        
        elif user.role == 'admin':
            # Admin stats
            stats = {
                "total_users": User.objects.count(),
                "active_users": User.objects.filter(is_active=True).count(),
                "total_forms": ClearanceForm.objects.count(),
            }
        
        return Response({
            "user": user_data,
            "stats": stats,
            "profile_completion": profile_completion,
            "recent_activities": recent_activities[:5]
        })
        
    except Exception as e:
        print(f"Error getting complete profile: {e}")
        import traceback
        traceback.print_exc()
        return Response({"error": "Failed to load profile"}, status=500)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    """Get basic user profile"""
    try:
        user = request.user
        
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "phone": user.phone,
            "department": user.department.name if user.department else None,
            "department_id": user.department.id if user.department else None,
            "profile_picture_url": user.get_profile_picture_url(),
            "is_blocked": user.is_blocked,
            "is_active": user.is_active,
            "date_joined": user.date_joined,
            "last_login": user.last_login
        })
        
    except Exception as e:
        print(f"Error getting user profile: {e}")
        return Response({"error": "Failed to load profile"}, status=500)
def generate_thumbnail(image_data):
    try:
        # Check if image_data is bytes
        if isinstance(image_data, bytes):
            data = image_data
        else:
            # Assume it's already a BytesIO object
            data = image_data.getvalue() if hasattr(image_data, 'getvalue') else image_data
        
        # Open image
        img = Image.open(BytesIO(data))
        
        # Create thumbnail
        img.thumbnail((200, 200))
        
        # Save/return thumbnail
        output = BytesIO()
        img.save(output, format='JPEG', quality=85)
        return output.getvalue()
        
    except Exception as e:
        print(f"Thumbnail generation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_user_profile(request):
    """Update user profile information"""
    try:
        user = request.user
        
        # Update allowed fields
        allowed_fields = ['first_name', 'last_name', 'email', 'phone']
        updated = False
        
        for field in allowed_fields:
            if field in request.data:
                setattr(user, field, request.data[field])
                updated = True
        
        if updated:
            user.save()
            
            return Response({
                "message": "Profile updated successfully",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "role": user.role,
                    "phone": user.phone,
                    "department": user.department.name if user.department else None,
                    "profile_picture_url": user.get_profile_picture_url(),
                }
            })
        else:
            return Response({"error": "No valid fields to update"}, status=400)
        
    except Exception as e:
        print(f"Error updating profile: {e}")
        return Response({"error": "Failed to update profile"}, status=500)
    


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_user_password_view(request):
    """Change password for authenticated users"""
    try:
        user = request.user
        
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            return Response({"error": "All fields are required"}, status=400)
        
        if new_password != confirm_password:
            return Response({"error": "New passwords do not match"}, status=400)
        
        if len(new_password) < 8:
            return Response({"error": "Password must be at least 8 characters"}, status=400)
        
        # Verify current password
        if not user.check_password(current_password):
            return Response({"error": "Current password is incorrect"}, status=401)
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        # Create new token (optional - forces re-login on other devices)
        # Token.objects.filter(user=user).delete()
        # new_token = Token.objects.create(user=user)
        
        return Response({
            "message": "Password changed successfully",
            # "new_token": new_token.key if new_token else None
        })
        
    except Exception as e:
        print(f"Error changing password: {e}")
        return Response({"error": "Failed to change password"}, status=500)
    
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def upload_profile_picture_view(request):
    """Upload or update profile picture"""
    try:
        user = request.user
        
        if 'profile_picture' not in request.FILES:
            return Response({"error": "No image provided"}, status=400)
        
        file = request.FILES['profile_picture']
        
        # Validate file type
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
        file_ext = os.path.splitext(file.name)[1].lower()
        if file_ext not in allowed_extensions:
            return Response({"error": f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"}, status=400)
        
        # Validate file size (5MB max)
        if file.size > 5 * 1024 * 1024:
            return Response({"error": "File must be less than 5MB"}, status=400)
        
        # Delete old profile picture if exists
        if user.profile_picture:
            try:
                user.profile_picture.delete(save=False)
            except Exception as e:
                print(f"Error deleting old profile picture: {e}")
        
        # Save new profile picture
        user.profile_picture = file
        user.save()
        
        return Response({
            "message": "Profile picture uploaded successfully",
            "profile_picture_url": user.get_profile_picture_url()
        })
        
    except Exception as e:
        print(f"Error uploading profile picture: {e}")
        return Response({"error": "Failed to upload profile picture"}, status=500)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_profile_picture(request):
    """Remove profile picture"""
    try:
        user = request.user
        
        if not user.profile_picture:
            return Response({"error": "No profile picture to remove"}, status=400)
        
        # Delete the file
        user.profile_picture.delete(save=False)
        user.profile_picture = None
        user.save()
        
        return Response({
            "message": "Profile picture removed successfully",
            "profile_picture_url": user.get_profile_picture_url()
        })
        
    except Exception as e:
        print(f"Error removing profile picture: {e}")
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile_settings(request):
    """Get profile settings and preferences"""
    try:
        user = request.user
        
        # Get user's notification preferences (you can add this to User model)
        # For now, return basic settings
        settings = {
            "email_notifications": True,
            "push_notifications": True,
            "two_factor_auth": False,
            "privacy_public": False,
            "language": "en",
            "timezone": "UTC"
        }
        
        return Response({
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            },
            "settings": settings,
            "profile_completion": calculate_profile_completion(user)
        })
        
    except Exception as e:
        logger.error(f"Error getting profile settings: {e}")
        return Response({"error": "Failed to load settings"}, status=500)

def calculate_profile_completion(user):
    """Calculate profile completion percentage"""
    total_fields = 8  # Adjust based on your fields
    completed_fields = 0
    
    # Check each field
    if user.username: completed_fields += 1
    if user.email: completed_fields += 1
    if user.first_name: completed_fields += 1
    if user.last_name: completed_fields += 1
    if user.phone: completed_fields += 1
    if user.profile_picture: completed_fields += 1
    # Add more fields as needed
    
    return round((completed_fields / total_fields) * 100)


# ==================== DEBUG AUTH VIEW ====================
@api_view(['GET'])
def debug_auth_view(request):
    """Debug endpoint to check authentication"""
    print("Debug auth called")
    print("Headers:", dict(request.headers))
    auth_header = request.headers.get('Authorization', '')
    print("Auth Header:", auth_header)
    
    if not auth_header.startswith('Token '):
        return Response({"error": "No token provided or wrong format"}, status=401)
    
    token_key = auth_header.split(' ')[1]
    try:
        token = Token.objects.get(key=token_key)
        user = token.user
        return Response({
            "authenticated": True,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            },
            "token": token_key[:10] + "..."
        })
    except Token.DoesNotExist:
        return Response({"error": "Invalid token"}, status=401)


# ==================== PROFILE VIEWS ====================
@api_view(['GET'])
def get_complete_profile(request):
    """Get complete user profile with statistics"""
    try:
        print("=== PROFILE ENDPOINT CALLED ===")
        print("Headers:", dict(request.headers))
        
        # Get authentication token
        auth_header = request.headers.get('Authorization', '')
        print("Auth Header:", auth_header)
        
        if not auth_header.startswith('Token '):
            return Response({"error": "Authentication required. Token missing."}, status=401)
        
        token_key = auth_header.split(' ')[1]
        
        try:
            token = Token.objects.get(key=token_key)
            user = token.user
            print(f"User authenticated: {user.username} (ID: {user.id})")
        except Token.DoesNotExist:
            print("Invalid token")
            return Response({"error": "Invalid authentication token"}, status=401)
        
        # Prepare user data
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "role": user.role,
            "phone": user.phone or "",
            "department": user.department.name if user.department else None,
            "department_name": user.department.name if user.department else None,
            "department_id": user.department.id if user.department else None,
            "profile_picture_url": user.get_profile_picture_url(),
            "is_blocked": user.is_blocked,
            "is_active": user.is_active,
            "date_joined": user.date_joined,
            "last_login": user.last_login,
            "last_password_change": getattr(user, 'last_password_change', None),
        }
        
        # Calculate profile completion
        total_fields = 6
        completed_fields = 0
        if user.username: completed_fields += 1
        if user.email: completed_fields += 1
        if user.first_name: completed_fields += 1
        if user.last_name: completed_fields += 1
        if user.phone: completed_fields += 1
        if user.profile_picture: completed_fields += 1
        profile_completion = round((completed_fields / total_fields) * 100) if total_fields > 0 else 0
        
        # Get user statistics based on role
        stats = {}
        recent_activities = []
        
        if user.role == 'student':
            forms = ClearanceForm.objects.filter(student=user)
            stats = {
                "total_forms": forms.count(),
                "approved_forms": forms.filter(status="Cleared by Registrar").count(),
                "pending_forms": forms.filter(status__in=['pending_department', 'approved_department', 'approved_library', 'approved_cafeteria', 'approved_dormitory']).count(),
                "rejected_forms": forms.filter(status='rejected').count(),
            }
            
            recent_forms = forms.order_by('-created_at')[:3]
            recent_activities = [{
                "type": "form",
                "id": f.id,
                "title": f"Form #{f.id}",
                "description": f.status,
                "date": f.created_at,
                "status": f.status
            } for f in recent_forms]
        
        elif user.role == 'departmenthead':
            if user.department:
                dept_forms = ClearanceForm.objects.filter(department_name=user.department.name)
                stats = {
                    "total_forms": dept_forms.count(),
                    "pending_forms": dept_forms.filter(status="pending_department").count(),
                    "approved_forms": dept_forms.filter(status="approved_department").count(),
                    "rejected_forms": dept_forms.filter(status="rejected").count(),
                }
        
        elif user.role in ['librarian', 'cafeteria', 'dormitory']:
            department_map = {
                'librarian': 'library',
                'cafeteria': 'cafeteria',
                'dormitory': 'dormitory'
            }
            dept_type = department_map.get(user.role)
            if dept_type:
                payments = StudentPayment.objects.filter(department_type=dept_type)
                stats = {
                    "total_payments": payments.count(),
                    "pending_payments": payments.filter(status="pending").count(),
                    "verified_payments": payments.filter(status="verified").count(),
                    "rejected_payments": payments.filter(status="rejected").count(),
                }
        
        elif user.role == 'registrar':
            forms = ClearanceForm.objects.all()
            stats = {
                "total_forms": forms.count(),
                "cleared_forms": forms.filter(status="Cleared by Registrar").count(),
                "pending_forms": forms.filter(status="approved_dormitory").count(),
            }
        
        elif user.role == 'admin':
            stats = {
                "total_users": User.objects.count(),
                "active_users": User.objects.filter(is_active=True).count(),
                "total_forms": ClearanceForm.objects.count(),
            }
        
        print(f"Profile data prepared for {user.username}")
        return Response({
            "user": user_data,
            "stats": stats,
            "profile_completion": profile_completion,
            "recent_activities": recent_activities[:5]
        })
        
    except Exception as e:
        print(f"ERROR in get_complete_profile: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response({"error": "Internal server error"}, status=500)


# ==================== SIMPLIFIED AUTH VIEWS ====================
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view_simple(request):
    """Simple login view that returns token"""
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")
    role = request.data.get("role", "student")
    
    print(f"Login attempt: username={username}, email={email}, role={role}")
    
    user = None
    
    if role == "student":
        # Student login by email
        if not email:
            return Response({"error": "Email required for student login"}, status=400)
        try:
            user = User.objects.get(email=email, role="student")
            if not user.check_password(password):
                return Response({"error": "Invalid credentials"}, status=401)
        except User.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=401)
    else:
        # Staff login by username
        if not username:
            return Response({"error": "Username required"}, status=400)
        
        user = authenticate(username=username, password=password)
        if not user or user.role != role:
            return Response({"error": "Invalid credentials"}, status=401)
    
    if user.is_blocked:
        return Response({"error": "Account is blocked. Contact admin."}, status=403)
    
    # Get or create token
    token, created = Token.objects.get_or_create(user=user)
    
    # Store token in user model for debugging
    user.auth_token = token.key
    user.save()
    
    user_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "department": user.department.name if user.department else None,
        "department_id": user.department.id if user.department else None,
        "first_name": user.first_name,
        "last_name": user.last_name,
    }
    
    print(f"Login successful: {user.username}, token: {token.key[:10]}...")
    
    return Response({
        "token": token.key,
        "user": user_data
    })
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_profile_settings(request):
    """Update profile settings"""
    try:
        user = request.user
        data = request.data
        
        # You can add settings fields to User model or create a separate Settings model
        # For now, this is a placeholder
        
        return Response({
            "message": "Settings updated successfully",
            "settings": data
        })
        
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        return Response({"error": "Failed to update settings"}, status=500)



# ==================== CHAT VIEWSETS ====================

class ChatRoomViewSet(viewsets.ModelViewSet):
    """ViewSet for managing chat rooms - FIXED VERSION"""
    serializer_class = ChatRoomSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'student':
            return ChatRoom.objects.filter(
                Q(student=user) | Q(participants=user),
                is_active=True
            ).distinct().order_by('-last_message_time')
        elif user.role == 'departmenthead':
            return ChatRoom.objects.filter(
                Q(specific_staff=user) | Q(participants=user),
                is_active=True
            ).distinct().order_by('-last_message_time')
        else:
            # For other staff roles
            return ChatRoom.objects.filter(
                Q(specific_staff=user) | Q(participants=user),
                is_active=True
            ).distinct().order_by('-last_message_time')

    @action(detail=False, methods=['get'])
    def my_rooms(self, request):
        """Get chat rooms for current user"""
        rooms = self.get_queryset()
        serializer = self.get_serializer(rooms, many=True)
        return Response({
            'status': 'success',
            'data': serializer.data
        })

    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        """Mark all messages in a room as read"""
        room = self.get_object()
        user = request.user
        
        # Mark all unread messages as read (excluding user's own messages)
        updated_count = room.messages.filter(
            is_read=False
        ).exclude(sender=user).update(is_read=True)
        
        return Response({
            "message": f"{updated_count} messages marked as read",
            "status": "success"
        })

class MessageViewSet(viewsets.ModelViewSet):
    """ViewSet for managing messages - FIXED VERSION"""
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        room_id = self.request.query_params.get('room_id')
        if room_id:
            try:
                room = ChatRoom.objects.get(id=room_id, is_active=True)
                # Check if user is a participant
                if self.request.user in room.participants.all():
                    return room.messages.all().order_by('created_at')
            except ChatRoom.DoesNotExist:
                pass
        return Message.objects.none()

    def perform_create(self, serializer):
        room_id = self.request.data.get('room')
        try:
            room = ChatRoom.objects.get(id=room_id, is_active=True)
            # Check if user is a participant
            if self.request.user in room.participants.all():
                message = serializer.save(sender=self.request.user, room=room)
                
                # Update room's last message time
                room.last_message_time = message.created_at
                room.save(update_fields=['last_message_time'])
                
                # Create notification for other participants
                other_participants = room.participants.exclude(id=self.request.user.id)
                
                # Create notification content
                notification_content = message.content[:100] if message.content else f"Sent a {message.message_type}"
                
                notifications = []
                for participant in other_participants:
                    notifications.append(
                        Notification(
                            user=participant,
                            title=f"New message from {self.request.user.get_full_name() or self.request.user.username}",
                            message=notification_content,
                            notification_type='chat',
                            clearance_form=None
                        )
                    )
                
                # Bulk create notifications for better performance
                if notifications:
                    Notification.objects.bulk_create(notifications)
                    
        except ChatRoom.DoesNotExist:
            raise serializers.ValidationError({"error": "Chat room not found"})
        except Exception as e:
            raise serializers.ValidationError({"error": str(e)})

# ==================== CHAT FUNCTIONS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_chat_rooms(request):
    """Get chat rooms for the current user - FIXED VERSION"""
    user = request.user
    chat_rooms = []
    
    def get_room_data(room):
        # Get last message - return string ONLY
        last_message_obj = room.messages.last()
        last_message = ""
        if last_message_obj:
            last_message = last_message_obj.content[:100] if last_message_obj.content else f"[{last_message_obj.message_type}]"
        
        # Get unread count
        unread_count = room.messages.filter(
            is_read=False
        ).exclude(sender=user).count()
        
        room_data = {
            "id": room.id,
            "name": room.name,
            "room_type": room.room_type,
            "last_message": last_message,  # This is a string, NOT an object
            "last_message_time": room.last_message_time,
            "unread_count": unread_count,
            "created_at": room.created_at,
            "is_active": room.is_active
        }
        
        # Add participant info based on user role
        if user.role == 'student':
            other_participant = room.participants.exclude(id=user.id).first()
            if other_participant:
                room_data["other_participant"] = {
                    "id": other_participant.id,
                    "username": other_participant.username,
                    "name": other_participant.get_full_name(),
                    "role": other_participant.role,
                }
        else:
            # Staff view
            if room.student:
                room_data["student"] = {
                    "id": room.student.id,
                    "username": room.student.username,
                    "name": room.student.get_full_name(),
                    "email": room.student.email,
                }
            room_data["student_name"] = room.student.get_full_name() if room.student else "Unknown Student"
            room_data["student_email"] = room.student.email if room.student else ""
        
        return room_data
    
    if user.role == 'student':
        rooms = ChatRoom.objects.filter(
            participants=user,
            is_active=True
        ).order_by('-last_message_time')
        chat_rooms = [get_room_data(room) for room in rooms]
    
    elif user.role == 'departmenthead':
        rooms = ChatRoom.objects.filter(
            specific_staff=user,
            is_active=True
        ).order_by('-last_message_time')
        chat_rooms = [get_room_data(room) for room in rooms]
    
    return Response(chat_rooms)  # Return array directly
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_chat_with_department(request):
    """Student starts a chat with a department"""
    if request.user.role != 'student':
        return Response({"error": "Only students can start chats"}, status=403)

    user = request.user
    room_type = request.data.get('room_type')
    
    if not room_type:
        return Response({"error": "room_type is required"}, status=400)

    # Determine the staff based on room_type
    staff_user = None
    
    if room_type == 'student_department_head':
        if not user.department:
            return Response({"error": "You don't have a department assigned"}, status=400)
        
        staff_user = User.objects.filter(
            role='departmenthead',
            department=user.department,
            is_active=True
        ).first()
        
        if not staff_user:
            return Response({"error": f"No department head found for {user.department.name}"}, status=404)
            
    elif room_type == 'student_librarian':
        staff_user = User.objects.filter(role='librarian', is_active=True).first()
    elif room_type == 'student_cafeteria':
        staff_user = User.objects.filter(role='cafeteria', is_active=True).first()
    elif room_type == 'student_dormitory':
        staff_user = User.objects.filter(role='dormitory', is_active=True).first()
    elif room_type == 'student_registrar':
        staff_user = User.objects.filter(role='registrar', is_active=True).first()

    if not staff_user:
        return Response({"error": "No staff member available"}, status=404)

    # Check if chat already exists
    existing_chat = ChatRoom.objects.filter(
        student=user,
        specific_staff=staff_user,
        room_type=room_type,
        is_active=True
    ).first()

    if existing_chat:
        serializer = ChatRoomSerializer(existing_chat, context={'request': request})
        return Response({
            "message": "Chat already exists",
            "chat_room": serializer.data
        })

    # Create new chat room
    chat_room = ChatRoom.objects.create(
        name=f"{user.get_full_name() or user.username} - {staff_user.get_full_name() or staff_user.username}",
        room_type=room_type,
        student=user,
        department=user.department,
        specific_staff=staff_user,
        is_active=True
    )
    
    # Add participants
    chat_room.participants.add(user, staff_user)
    
    # Create welcome message
    welcome_msg = Message.objects.create(
        room=chat_room,
        sender=staff_user,
        message_type='text',
        content=f"Hello {user.get_full_name() or user.username}! This is {staff_user.get_full_name() or staff_user.username} from {staff_user.role.replace('departmenthead', 'Department Head').title()}. How can I help you with your clearance?"
    )
    
    chat_room.last_message_time = welcome_msg.created_at
    chat_room.save()
    
    # Create notification for staff
    Notification.objects.create(
        user=staff_user,
        title="New Chat Request",
        message=f"Student {user.get_full_name() or user.username} started a chat with you.",
        notification_type='chat'
    )

    serializer = ChatRoomSerializer(chat_room, context={'request': request})
    
    return Response({
        "message": "Chat started successfully",
        "chat_room": serializer.data
    }, status=201)
    


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def staff_start_chat_with_student(request):
    """Staff starts a chat with a student"""
    staff_roles = ['departmenthead', 'librarian', 'cafeteria', 'dormitory', 'registrar']
    
    if request.user.role not in staff_roles:
        return Response({"error": "Unauthorized - Staff only"}, status=403)

    student_id = request.data.get('student_id')
    if not student_id:
        return Response({"error": "Student ID required"}, status=400)

    try:
        student = User.objects.get(id=student_id, role='student')
        staff = request.user
        
        # Determine room type based on staff role
        room_type_map = {
            'departmenthead': 'student_department_head',
            'librarian': 'student_librarian',
            'cafeteria': 'student_cafeteria',
            'dormitory': 'student_dormitory',
            'registrar': 'student_registrar'
        }
        
        room_type = room_type_map.get(staff.role)
        
        if not room_type:
            return Response({"error": "Invalid staff role"}, status=400)
        
        # Check if chat already exists
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=staff,
            room_type=room_type,
            is_active=True
        ).first()

        if existing_chat:
            serializer = ChatRoomSerializer(existing_chat, context={'request': request})
            return Response({
                "message": "Chat already exists",
                "chat_room": serializer.data
            })

        # Create new chat room
        chat_room = ChatRoom.objects.create(
            name=f"{student.get_full_name() or student.username} - {staff.get_full_name() or staff.username}",
            room_type=room_type,
            student=student,
            department=student.department,
            specific_staff=staff,
            is_active=True
        )
        
        # Add participants
        chat_room.participants.add(student, staff)
        
        # Create welcome message
        welcome_msg = Message.objects.create(
            room=chat_room,
            sender=staff,
            message_type='text',
            content=f"Hello {student.get_full_name() or student.username}! This is {staff.get_full_name() or staff.username} from {staff.role.title()}. How can I help you with your clearance?"
        )
        
        chat_room.last_message_time = welcome_msg.created_at
        chat_room.save()
        
        # Create notification for student
        Notification.objects.create(
            user=student,
            title="New Chat Request",
            message=f"{staff.get_full_name() or staff.username} from {staff.role.title()} started a chat with you.",
            notification_type='chat'
        )

        serializer = ChatRoomSerializer(chat_room, context={'request': request})
        
        return Response({
            "message": "Chat started successfully",
            "chat_room": serializer.data
        }, status=201)
        
    except User.DoesNotExist:
        return Response({"error": "Student not found"}, status=404)
    except Exception as e:
        return Response({"error": f"Failed to start chat: {str(e)}"}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_chat_messages(request, room_id):
    """Get messages for a specific chat room with pagination"""
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # FIRST: Mark unread messages as read - DO THIS BEFORE PAGINATION/SLICING
        Message.objects.filter(
            room=chat_room,
            is_read=False
        ).exclude(sender=user).update(is_read=True)
        
        # Pagination
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        
        # Get messages
        messages = chat_room.messages.all().order_by('-created_at')
        total_messages = messages.count()
        messages_page = messages[start:end]
        serializer = MessageSerializer(
            messages_page, 
            many=True, 
            context={'request': request}
        )
        
        # Get room info
        room_serializer = ChatRoomSerializer(
            chat_room, 
            context={'request': request}
        )
        
        return Response({
            'room': room_serializer.data,
            'messages': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': (total_messages + page_size - 1) // page_size,
                'total_messages': total_messages,
                'has_next': end < total_messages,
                'has_previous': page > 1
            }
        })
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser, JSONParser])
def send_message(request):
    """Send a message with support for text, images, audio, video, and files - FIXED VERSION"""
    room_id = request.data.get('room_id')
    content = request.data.get('content', '')
    message_type = request.data.get('message_type', 'text')
    reply_to_id = request.data.get('reply_to')
    
    if not room_id:
        return Response({"error": "room_id is required"}, status=400)

    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Handle different message types
        message_data = {
            'room': chat_room,
            'sender': user,
            'message_type': message_type,
            'content': content
        }
        
        # Handle reply
        if reply_to_id:
            try:
                reply_to_msg = Message.objects.get(id=reply_to_id)
                message_data['reply_to'] = reply_to_msg
            except Message.DoesNotExist:
                pass
        
        # Handle file uploads based on message type
        if message_type == 'image':
            if 'image_file' in request.FILES:
                image_file = request.FILES['image_file']
                message_data['image_file'] = image_file
                message_data['file_name'] = image_file.name
                message_data['file_size'] = image_file.size
                
                # Generate thumbnail for image
                try:
                    from PIL import Image
                    from io import BytesIO
                    from django.core.files.base import ContentFile
                    
                    img = Image.open(image_file)
                    img.thumbnail((200, 200))
                    thumb_io = BytesIO()
                    img.save(thumb_io, format='JPEG', quality=85)
                    
                    message_data['thumbnail'] = ContentFile(
                        thumb_io.getvalue(),
                        name=f"thumb_{image_file.name}"
                    )
                except Exception as e:
                    print(f"Thumbnail generation failed: {e}")
                    
        elif message_type == 'audio':
            if 'audio_file' in request.FILES:
                audio_file = request.FILES['audio_file']
                message_data['audio_file'] = audio_file
                message_data['file_name'] = audio_file.name
                message_data['file_size'] = audio_file.size
                
                # Get duration if provided
                duration = request.data.get('duration')
                if duration:
                    try:
                        message_data['duration'] = float(duration)
                    except ValueError:
                        pass
                        
        elif message_type == 'video':
            if 'video_file' in request.FILES:
                video_file = request.FILES['video_file']
                message_data['video_file'] = video_file
                message_data['file_name'] = video_file.name
                message_data['file_size'] = video_file.size
                
                # Get duration if provided
                duration = request.data.get('duration')
                if duration:
                    try:
                        message_data['duration'] = float(duration)
                    except ValueError:
                        pass
                        
        elif message_type == 'file':
            if 'file' in request.FILES:
                file_obj = request.FILES['file']
                message_data['file'] = file_obj
                message_data['file_name'] = file_obj.name
                message_data['file_size'] = file_obj.size
        
        # Create message
        message = Message.objects.create(**message_data)
        
        # Update room's last message time
        chat_room.last_message_time = message.created_at
        chat_room.save(update_fields=['last_message_time'])
        
        # Create notifications for other participants
        other_participants = chat_room.participants.exclude(id=user.id)
        
        notification_content = content[:100] if content else f"Sent a {message_type}"
        if not content and message_type != 'text':
            notification_content = f"Sent a {message_type}"
        
        notifications = []
        for participant in other_participants:
            notifications.append(
                Notification(
                    user=participant,
                    title=f"New message from {user.get_full_name() or user.username}",
                    message=notification_content,
                    notification_type='chat'
                )
            )
        
        if notifications:
            Notification.objects.bulk_create(notifications)
        
        # Serialize and return
        serializer = MessageSerializer(message, context={'request': request})
        
        return Response({
            "status": "success",
            "message": "Message sent successfully",
            "data": serializer.data
        }, status=201)
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"error": str(e)}, status=500)
    
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def department_staff_list(request):
    """Get list of department staff for chat"""
    user = request.user
    
    if user.role == 'student':
        departments = []
        
        # Department Head - Check if student has a department
        if user.department:
            dept_head = User.objects.filter(
                role='departmenthead',
                department=user.department,  # Same department
                is_active=True
            ).first()
            departments.append({
                'role': 'department_head',
                'room_type': 'student_department_head',
                'name': 'Department Head',
                'description': f'Chat with your {user.department.name} Department Head',
                'available': dept_head is not None,
                'icon': '👨‍🏫',
                'staff_name': dept_head.get_full_name() if dept_head else None,
                'staff_id': dept_head.id if dept_head else None
            })
        else:
            departments.append({
                'role': 'department_head',
                'room_type': 'student_department_head',
                'name': 'Department Head',
                'description': 'You need to be assigned to a department first',
                'available': False,
                'icon': '👨‍🏫',
                'staff_name': None
            })
        
        # Librarian
        librarian = User.objects.filter(role='librarian', is_active=True).first()
        departments.append({
            'role': 'librarian',
            'room_type': 'student_librarian',
            'name': 'Librarian',
            'description': 'Chat about library books, dues, and fines',
            'available': librarian is not None,
            'icon': '📚',
            'staff_name': librarian.get_full_name() if librarian else None,
            'staff_id': librarian.id if librarian else None
        })
        
        # Cafeteria
        cafeteria = User.objects.filter(role='cafeteria', is_active=True).first()
        departments.append({
            'role': 'cafeteria',
            'room_type': 'student_cafeteria',
            'name': 'Cafeteria',
            'description': 'Chat about meal dues and cafeteria issues',
            'available': cafeteria is not None,
            'icon': '🍽️',
            'staff_name': cafeteria.get_full_name() if cafeteria else None,
            'staff_id': cafeteria.id if cafeteria else None
        })
        
        # Dormitory
        dormitory = User.objects.filter(role='dormitory', is_active=True).first()
        departments.append({
            'role': 'dormitory',
            'room_type': 'student_dormitory',
            'name': 'Dormitory',
            'description': 'Chat about dormitory damages and accommodation',
            'available': dormitory is not None,
            'icon': '🏠',
            'staff_name': dormitory.get_full_name() if dormitory else None,
            'staff_id': dormitory.id if dormitory else None
        })
        
        # Registrar
        registrar = User.objects.filter(role='registrar', is_active=True).first()
        departments.append({
            'role': 'registrar',
            'room_type': 'student_registrar',
            'name': 'Registrar',
            'description': 'Chat about final clearance and certificates',
            'available': registrar is not None,
            'icon': '📋',
            'staff_name': registrar.get_full_name() if registrar else None,
            'staff_id': registrar.id if registrar else None
        })
        
        return Response(departments)
    
    elif user.role == 'departmenthead':
        # Return students in the department
        if not user.department:
            return Response({"error": "No department assigned"}, status=400)
        
        students = User.objects.filter(
            role='student',
            department=user.department,
            is_active=True
        ).order_by('username')
        
        student_list = []
        for student in students:
            # Check if there's an existing chat
            existing_chat = ChatRoom.objects.filter(
                student=student,
                specific_staff=user,
                room_type='student_department_head',
                is_active=True
            ).first()
            
            student_list.append({
                'id': student.id,
                'name': student.get_full_name(),
                'username': student.username,
                'email': student.email,
                'id_number': student.id_number,
                'has_chat': existing_chat is not None,
                'chat_room_id': existing_chat.id if existing_chat else None,
                'last_message': existing_chat.last_message_time if existing_chat else None
            })
        
        return Response({
            'role': 'departmenthead',
            'department': user.department.name,
            'students': student_list
        })
    
    else:
        return Response({"error": "Role not supported for chat"}, status=400)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_departments_for_chat(request):
    """Get available departments for chat (alias for department_staff_list)"""
    return department_staff_list(request)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_unread_message_count(request):
    """Get unread message count for user"""
    user = request.user
    
    chat_rooms = ChatRoom.objects.filter(
        participants=user,
        is_active=True
    )
    
    total_unread = 0
    rooms_data = []
    
    for room in chat_rooms:
        unread_count = room.messages.filter(
            is_read=False
        ).exclude(sender=user).count()
        
        total_unread += unread_count
        
        rooms_data.append({
            'room_id': room.id,
            'room_name': room.name,
            'unread_count': unread_count,
            'last_message_time': room.last_message_time
        })
    
    return Response({
        'user_id': user.id,
        'total_unread': total_unread,
        'rooms': rooms_data
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_messages_as_read(request):
    """Mark messages in a room as read"""
    room_id = request.data.get('room_id')
    message_ids = request.data.get('message_ids', [])
    
    if not room_id and not message_ids:
        return Response({"error": "room_id or message_ids required"}, status=400)
    
    user = request.user
    
    try:
        if room_id:
            chat_room = ChatRoom.objects.get(id=room_id)
            
            if user not in chat_room.participants.all():
                return Response({"error": "Not a participant"}, status=403)
            
            messages = chat_room.messages.filter(
                is_read=False
            ).exclude(sender=user)
            
            for msg in messages:
                msg.mark_as_read(user)
                
            return Response({
                "message": f"Marked {messages.count()} messages as read",
                "count": messages.count()
            })
            
        elif message_ids:
            messages = Message.objects.filter(id__in=message_ids)
            
            for msg in messages:
                if user in msg.room.participants.all():
                    msg.mark_as_read(user)
            
            return Response({
                "message": f"Marked {len(message_ids)} messages as read"
            })
            
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_department_staff_list(request):
    """Get available staff for student to chat with"""
    if request.user.role != 'student':
        return Response({"error": "Only students can access this"}, status=403)
    
    student = request.user
    staff_list = []
    
    # Department Head
    if student.department:
        dept_head = User.objects.filter(
            role='departmenthead',
            department=student.department,
            is_active=True
        ).first()
        
        staff_list.append({
            'role': 'department_head',
            'room_type': 'student_department_head',
            'name': 'Department Head',
            'department': student.department.name if student.department else None,
            'available': dept_head is not None,
            'staff': {
                'id': dept_head.id if dept_head else None,
                'name': dept_head.get_full_name() if dept_head else None,
                'email': dept_head.email if dept_head else None
            } if dept_head else None,
            'icon': '👨‍🏫',
            'description': f'Chat with your department head about clearance requirements'
        })
    
    # Librarian
    librarian = User.objects.filter(role='librarian', is_active=True).first()
    staff_list.append({
        'role': 'librarian',
        'room_type': 'student_librarian',
        'name': 'Librarian',
        'available': librarian is not None,
        'staff': {
            'id': librarian.id if librarian else None,
            'name': librarian.get_full_name() if librarian else None,
            'email': librarian.email if librarian else None
        } if librarian else None,
        'icon': '📚',
        'description': 'Chat about library books, dues, and fines'
    })
    
    # Cafeteria
    cafeteria = User.objects.filter(role='cafeteria', is_active=True).first()
    staff_list.append({
        'role': 'cafeteria',
        'room_type': 'student_cafeteria',
        'name': 'Cafeteria',
        'available': cafeteria is not None,
        'staff': {
            'id': cafeteria.id if cafeteria else None,
            'name': cafeteria.get_full_name() if cafeteria else None,
            'email': cafeteria.email if cafeteria else None
        } if cafeteria else None,
        'icon': '🍽️',
        'description': 'Chat about meal dues and cafeteria issues'
    })
    
    # Dormitory
    dormitory = User.objects.filter(role='dormitory', is_active=True).first()
    staff_list.append({
        'role': 'dormitory',
        'room_type': 'student_dormitory',
        'name': 'Dormitory',
        'available': dormitory is not None,
        'staff': {
            'id': dormitory.id if dormitory else None,
            'name': dormitory.get_full_name() if dormitory else None,
            'email': dormitory.email if dormitory else None
        } if dormitory else None,
        'icon': '🏠',
        'description': 'Chat about dormitory damages and accommodation'
    })
    
    # Registrar
    registrar = User.objects.filter(role='registrar', is_active=True).first()
    staff_list.append({
        'role': 'registrar',
        'room_type': 'student_registrar',
        'name': 'Registrar',
        'available': registrar is not None,
        'staff': {
            'id': registrar.id if registrar else None,
            'name': registrar.get_full_name() if registrar else None,
            'email': registrar.email if registrar else None
        } if registrar else None,
        'icon': '📋',
        'description': 'Chat about final clearance and certificates'
    })
    
    return Response(staff_list)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_students_for_staff(request):
    """Get list of students for department head/staff"""
    user = request.user
    
    if user.role not in ['departmenthead', 'librarian', 'cafeteria', 'dormitory', 'registrar']:
        return Response({"error": "Unauthorized"}, status=403)
    
    # Filter students based on department for department head
    if user.role == 'departmenthead':
        students = User.objects.filter(
            role='student',
            department=user.department,
            is_active=True
        ).order_by('first_name', 'last_name')
    else:
        # For other staff, get all students
        students = User.objects.filter(
            role='student',
            is_active=True
        ).order_by('first_name', 'last_name')
    
    result = []
    for student in students[:50]:  # Limit to 50 students
        # Check if chat exists
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=user,
            is_active=True
        ).first()
        
        result.append({
            'id': student.id,
            'full_name': student.get_full_name() or student.username,
            'username': student.username,
            'email': student.email,
            'id_number': getattr(student, 'id_number', 'N/A'),
            'program': getattr(student, 'program_level', 'N/A'),
            'department': student.department.name if student.department else None,
            'has_existing_chat': existing_chat is not None,
            'chat_room_id': existing_chat.id if existing_chat else None,
            'last_login': student.last_login
        })
    
    return Response(result)



@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_message(request, message_id):
    """Delete a message"""
    try:
        message = Message.objects.get(id=message_id)
        
        if message.sender != request.user:
            return Response({"error": "You can only delete your own messages"}, status=403)
        
        # Delete associated files
        if message.image_file:
            message.image_file.delete(save=False)
        if message.audio_file:
            message.audio_file.delete(save=False)
        if message.video_file:
            message.video_file.delete(save=False)
        if message.file:
            message.file.delete(save=False)
        if message.thumbnail:
            message.thumbnail.delete(save=False)
        
        message.delete()
        
        return Response({"message": "Message deleted successfully"})
        
    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=404)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def stream_media(request, message_id):
    """Stream audio/video files"""
    try:
        message = Message.objects.get(id=message_id)
        user = request.user
        
        # Check if user is participant
        if user not in message.room.participants.all():
            return Response({"error": "Unauthorized"}, status=403)
        
        # Get file path
        if message.audio_file:
            file_path = message.audio_file.path
            content_type = 'audio/mpeg'
        elif message.video_file:
            file_path = message.video_file.path
            content_type = 'video/mp4'
        else:
            return Response({"error": "No media file found"}, status=404)
        
        # Stream file
        if os.path.exists(file_path):
            response = FileResponse(
                open(file_path, 'rb'),
                content_type=content_type
            )
            response['Content-Disposition'] = f'inline; filename="{os.path.basename(file_path)}"'
            return response
        else:
            return Response({"error": "File not found"}, status=404)
            
    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=404)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_file(request, message_id):
    """Download file from message"""
    try:
        message = Message.objects.get(id=message_id)
        user = request.user
        
        # Check if user is participant
        if user not in message.room.participants.all():
            return Response({"error": "Unauthorized"}, status=403)
        
        # Get file path
        if message.file:
            file_path = message.file.path
            content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        elif message.image_file:
            file_path = message.image_file.path
            content_type = mimetypes.guess_type(file_path)[0] or 'image/jpeg'
        elif message.audio_file:
            file_path = message.audio_file.path
            content_type = mimetypes.guess_type(file_path)[0] or 'audio/mpeg'
        elif message.video_file:
            file_path = message.video_file.path
            content_type = mimetypes.guess_type(file_path)[0] or 'video/mp4'
        else:
            return Response({"error": "No file found"}, status=404)
        
        # Download file
        if os.path.exists(file_path):
            response = FileResponse(
                open(file_path, 'rb'),
                content_type=content_type
            )
            filename = message.file_name or os.path.basename(file_path)
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        else:
            return Response({"error": "File not found"}, status=404)
            
    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=404)


class DepartmentStaffView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get staff list for chat (compatibility endpoint)"""
        return department_staff_list(request)

# ==================== STUDENT-SPECIFIC CHAT VIEWS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def student_get_chat_rooms(request):
    """Get chat rooms for student"""
    if request.user.role != 'student':
        return Response({"error": "Unauthorized - Student only"}, status=403)
    
    student = request.user
    rooms = ChatRoom.objects.filter(
        student=student,
        is_active=True
    ).prefetch_related(
        Prefetch('messages', queryset=Message.objects.order_by('-created_at')[:1], to_attr='last_msg')
    ).order_by('-last_message_time')
    
    serializer = ChatRoomSerializer(rooms, many=True, context={'request': request})
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def student_start_chat(request):
    """Student starts a chat with a department"""
    if request.user.role != 'student':
        return Response({"error": "Only students can start chats"}, status=403)
    
    # Alias to the main start_chat_with_department function
    return start_chat_with_department(request)

# ==================== DEPARTMENT HEAD-SPECIFIC CHAT VIEWS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def department_head_get_chat_rooms(request):
    """Get chat rooms for department head - FIXED VERSION"""
    user = request.user
    
    if user.role != 'departmenthead':
        return Response({"error": "Unauthorized"}, status=403)
    
    rooms = ChatRoom.objects.filter(
        specific_staff=user,
        is_active=True
    ).order_by('-last_message_time')
    
    result = []
    for room in rooms:
        # Get last message as string
        last_msg = room.messages.last()
        last_message = ""
        if last_msg:
            last_message = last_msg.content[:100] if last_msg.content else f"[{last_msg.message_type}]"
        
        # Get unread count
        unread_count = room.messages.filter(
            is_read=False
        ).exclude(sender=user).count()
        
        result.append({
            "id": room.id,
            "name": room.name,
            "room_type": room.room_type,
            "last_message": last_message,  # This is a string
            "last_message_time": room.last_message_time,
            "unread_count": unread_count,
            "student_name": room.student.get_full_name() if room.student else "Unknown Student",
            "student_email": room.student.email if room.student else "",
            "student_id": room.student.id if room.student else None,
            "created_at": room.created_at
        })
    
    return Response(result)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def staff_get_chat_rooms(request, role):
    """Generic staff get chat rooms"""
    staff_roles = ['librarian', 'cafeteria', 'dormitory', 'registrar']
    
    if request.user.role not in staff_roles:
        return Response({"error": "Unauthorized - Staff only"}, status=403)
    
    staff = request.user
    
    # Map role to room type
    room_type_map = {
        'librarian': 'student_librarian',
        'cafeteria': 'student_cafeteria', 
        'dormitory': 'student_dormitory',
        'registrar': 'student_registrar'
    }
    
    room_type = room_type_map.get(request.user.role)
    
    rooms = ChatRoom.objects.filter(
        Q(specific_staff=staff) | Q(participants=staff),
        is_active=True
    )
    
    if room_type:
        rooms = rooms.filter(room_type=room_type)
    
    rooms = rooms.distinct().prefetch_related(
        Prefetch('messages', queryset=Message.objects.order_by('-created_at')[:1], to_attr='last_msg')
    ).order_by('-last_message_time')
    
    serializer = ChatRoomSerializer(rooms, many=True, context={'request': request})
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_chat_rooms_by_role(request):
    """Get chat rooms based on user role"""
    user = request.user
    
    if user.role == 'student':
        return student_get_chat_rooms(request)
    elif user.role == 'departmenthead':
        return department_head_get_chat_rooms(request)
    elif user.role in ['librarian', 'cafeteria', 'dormitory', 'registrar']:
        return staff_get_chat_rooms(request, user.role)
    else:
        return Response({"error": "Role not supported"}, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def department_head_get_students(request):
    """Get students for department head to chat with - Only from their department"""
    if request.user.role != 'departmenthead':
        return Response({"error": "Only department heads can access this"}, status=403)
    
    department_head = request.user
    department = department_head.department
    
    if not department:
        return Response({"error": "No department assigned"}, status=400)
    
    # Get students from the same department ONLY
    students = User.objects.filter(
        role='student',
        department=department,  # Only students in this department
        is_active=True
    ).order_by('username')
    
    data = []
    for student in students:
        # Check if there's an existing chat
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=department_head,
            is_active=True
        ).first()
        
        data.append({
            "id": student.id,
            "username": student.username,
            "full_name": student.get_full_name(),
            "email": student.email,
            "id_number": student.id_number,
            "department": student.department.name if student.department else None,
            "has_existing_chat": existing_chat is not None,
            "chat_room_id": existing_chat.id if existing_chat else None,
            "last_login": student.last_login
        })
    
    return Response({
        'department_head': department_head.get_full_name(),
        'department': department.name,
        'total_students': len(data),
        'students': data
    })

# ==================== GET DEPARTMENT HEADS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_department_heads(request):
    """Get all department heads for student reference"""
    if request.user.role != 'student':
        return Response({"error": "Only students can access this"}, status=403)
    
    department_heads = User.objects.filter(
        role='departmenthead',
        is_active=True
    ).select_related('department')
    
    response_data = []
    for dh in department_heads:
        response_data.append({
            "id": dh.id,
            "name": dh.get_full_name() or dh.username,
            "department": dh.department.name if dh.department else "No department",
            "email": dh.email,
            "phone": dh.phone
        })
    
    return Response(response_data)



# ==================== CHAT ENDPOINTS FOR DORMITORY ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dormitory_get_chat_rooms(request):
    """Get chat rooms for dormitory staff"""
    user = request.user
    
    if user.role != 'dormitory':
        return Response({"error": "Unauthorized"}, status=403)
    
    rooms = ChatRoom.objects.filter(
        specific_staff=user,
        is_active=True
    ).order_by('-last_message_time')
    
    result = []
    for room in rooms:
        # Get last message as string
        last_msg = room.messages.last()
        last_message = ""
        if last_msg:
            last_message = last_msg.content[:100] if last_msg.content else f"[{last_msg.message_type}]"
        
        # Get unread count
        unread_count = room.messages.filter(
            is_read=False
        ).exclude(sender=user).count()
        
        result.append({
            "id": room.id,
            "name": room.name,
            "room_type": room.room_type,
            "last_message": last_message,  # This is a string
            "last_message_time": room.last_message_time,
            "unread_count": unread_count,
            "student_id": room.student.id if room.student else None,
            "student_name": room.student.get_full_name() if room.student else "Unknown Student",
            "student_email": room.student.email if room.student else "",
            "student_username": room.student.username if room.student else "",
            "created_at": room.created_at
        })
    
    return Response(result)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dormitory_get_students(request):
    """Get list of students for dormitory staff to start chats"""
    user = request.user
    
    if user.role != 'dormitory':
        return Response({"error": "Unauthorized"}, status=403)
    
    # Get all active students
    students = User.objects.filter(
        role='student',
        is_active=True
    ).order_by('first_name', 'last_name')
    
    result = []
    for student in students[:50]:  # Limit to 50 students for performance
        # Check if chat already exists with this student
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=user,
            room_type='student_dormitory',
            is_active=True
        ).first()
        
        # Get unread count if chat exists
        unread_count = 0
        if existing_chat:
            unread_count = existing_chat.messages.filter(
                is_read=False
            ).exclude(sender=user).count()
        
        result.append({
            'id': student.id,
            'full_name': student.get_full_name() or student.username,
            'username': student.username,
            'email': student.email,
            'id_number': getattr(student, 'id_number', 'N/A'),
            'program': getattr(student, 'program_level', 'N/A'),
            'department': student.department.name if student.department else None,
            'has_existing_chat': existing_chat is not None,
            'chat_room_id': existing_chat.id if existing_chat else None,
            'unread_count': unread_count,
            'last_login': student.last_login
        })
    
    return Response(result)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def dormitory_start_chat(request):
    """Dormitory staff starts a chat with a student"""
    user = request.user
    
    if user.role != 'dormitory':
        return Response({"error": "Unauthorized"}, status=403)

    student_id = request.data.get('student_id')
    if not student_id:
        return Response({"error": "Student ID required"}, status=400)

    try:
        student = User.objects.get(id=student_id, role='student')
        staff = user
        
        # Check if chat already exists
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=staff,
            room_type='student_dormitory',
            is_active=True
        ).first()

        if existing_chat:
            return Response({
                "message": "Chat already exists",
                "chat_room_id": existing_chat.id,
                "room_id": existing_chat.id
            })

        # Create new chat room
        chat_room = ChatRoom.objects.create(
            name=f"{student.get_full_name() or student.username} - Dormitory",
            room_type='student_dormitory',
            student=student,
            department=student.department,
            specific_staff=staff,
            is_active=True
        )
        
        # Add participants
        chat_room.participants.add(student, staff)
        
        # Create welcome message
        welcome_msg = Message.objects.create(
            room=chat_room,
            sender=staff,
            message_type='text',
            content=f"Hello {student.get_full_name() or student.username}! This is {staff.get_full_name() or staff.username} from Dormitory. How can I help you with your clearance?"
        )
        
        chat_room.last_message_time = welcome_msg.created_at
        chat_room.save()
        
        # Create notification for student
        Notification.objects.create(
            user=student,
            title="New Chat Request",
            message=f"{staff.get_full_name() or staff.username} from Dormitory started a chat with you.",
            notification_type='chat'
        )

        return Response({
            "message": "Chat started successfully",
            "chat_room_id": chat_room.id,
            "room_id": chat_room.id
        }, status=201)
        
    except User.DoesNotExist:
        return Response({"error": "Student not found"}, status=404)
    except Exception as e:
        return Response({"error": f"Failed to start chat: {str(e)}"}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def dormitory_send_message(request):
    """Send a message from dormitory staff"""
    if request.user.role != 'dormitory':
        return Response({"error": "Unauthorized"}, status=403)
    
    return send_message(request) 

# ==================== STUDENT CHAT ENDPOINTS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def student_get_chat_rooms(request):
    """Get chat rooms for student"""
    if request.user.role != 'student':
        return Response({"error": "Unauthorized - Student only"}, status=403)
    
    student = request.user
    rooms = ChatRoom.objects.filter(
        student=student,
        is_active=True
    ).order_by('-last_message_time')
    
    chat_rooms = []
    for room in rooms:
        # Get staff info
        staff = room.specific_staff
        
        # Get last message
        last_message = room.messages.last()
        
        # Get unread count (messages not from this student)
        unread_count = room.messages.filter(
            is_read=False
        ).exclude(sender=student).count()
        
        chat_rooms.append({
            "id": room.id,
            "room_name": room.name,
            "room_type": room.room_type,
            "staff_name": staff.get_full_name() if staff else None,
            "staff_role": staff.role if staff else None,
            "last_message": last_message.content if last_message else "",
            "last_message_time": room.last_message_time,
            "unread_count": unread_count,
            "created_at": room.created_at
        })
    
    return Response(chat_rooms)

# ==================== UNIFIED CHAT MESSAGES ENDPOINT ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_chat_messages_unified(request, room_id):
    """Get messages for a specific chat room (unified for all roles)"""
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Mark unread messages as read (excluding user's own messages)
        Message.objects.filter(
            room=chat_room,
            is_read=False
        ).exclude(sender=user).update(is_read=True)
        
        # Get messages
        messages = chat_room.messages.all().order_by('created_at')
        
        # Format messages
        formatted_messages = []
        for message in messages:
            formatted_messages.append({
                "id": message.id,
                "content": message.content,
                "sender": {
                    "id": message.sender.id if message.sender else None,
                    "username": message.sender.username if message.sender else None,
                    "name": message.sender.get_full_name() if message.sender else None,
                    "role": message.sender.role if message.sender else None
                },
                "file": message.file.url if message.file else None,
                "is_read": message.is_read,
                "created_at": message.created_at,
                "is_own": message.sender == user
            })
        
        # Get room info
        room_info = {
            'room_id': chat_room.id,
            'room_name': chat_room.name,
            'room_type': chat_room.room_type,
            'student': {
                'id': chat_room.student.id if chat_room.student else None,
                'name': chat_room.student.get_full_name() if chat_room.student else None,
                'email': chat_room.student.email if chat_room.student else None
            } if chat_room.student else None,
            'specific_staff': {
                'id': chat_room.specific_staff.id if chat_room.specific_staff else None,
                'name': chat_room.specific_staff.get_full_name() if chat_room.specific_staff else None,
                'role': chat_room.specific_staff.role if chat_room.specific_staff else None
            } if chat_room.specific_staff else None
        }
        
        return Response({
            'room': room_info,
            'messages': formatted_messages,
            'total_messages': messages.count()
        })
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)

# ==================== UNIFIED SEND MESSAGE ENDPOINT ====================

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_chat_message_unified(request):
    """Send a message in a chat room (unified for all roles)"""
    room_id = request.data.get('room_id')
    content = request.data.get('content')
    file = request.FILES.get('file')
    
    if not room_id or (not content and not file):
        return Response({"error": "room_id and content or file required"}, status=400)
    
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Create message
        message = Message.objects.create(
            room=chat_room,
            sender=user,
            content=content or "",
            file=file
        )
        
        # Update room's last message time
        chat_room.last_message_time = message.created_at
        chat_room.save()
        
        # Create notification for other participants
        other_participants = chat_room.participants.exclude(id=user.id)
        for participant in other_participants:
            Notification.objects.create(
                user=participant,
                title=f"New message from {user.get_full_name() or user.username}",
                message=content[:100] if content else "New file received",
                clearance_form=chat_room.student.clearance_forms.first() if hasattr(chat_room.student, 'clearance_forms') else None
            )
        
        return Response({
            "message": "Message sent successfully",
            "message_id": message.id,
            "content": message.content,
            "sender": {
                "id": user.id,
                "username": user.username,
                "name": user.get_full_name() or user.username
            },
            "created_at": message.created_at,
            "is_own": True
        }, status=201)
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)



# ==================== LIBRARIAN CHAT ENDPOINTS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def librarian_get_chat_rooms(request):
    """Get chat rooms for librarian"""
    if request.user.role != "librarian":
        return Response({"error": "Unauthorized - Librarian access only"}, status=403)
    
    librarian = request.user
    
    # Get chat rooms where librarian is a participant
    rooms = ChatRoom.objects.filter(
        Q(specific_staff=librarian) | Q(participants=librarian),
        is_active=True,
        room_type='student_librarian'
    ).distinct().order_by('-last_message_time')
    
    chat_rooms = []
    for room in rooms:
        # Get student info
        student = room.student
        
        # Get last message
        last_message = room.messages.last()
        
        # Get unread count (messages not from this librarian)
        unread_count = room.messages.filter(
            is_read=False
        ).exclude(sender=librarian).count()
        
        chat_rooms.append({
            "id": room.id,
            "student_id": student.id if student else None,
            "student_name": student.get_full_name() if student else "Unknown Student",
            "student_email": student.email if student else None,
            "last_message": last_message.content[:100] if last_message else "",
            "last_message_time": room.last_message_time,
            "unread_count": unread_count,
            "created_at": room.created_at
        })
    
    return Response(chat_rooms)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def librarian_get_chat_messages(request, room_id):
    """Get messages for a specific chat room"""
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Mark unread messages as read (excluding user's own messages)
        Message.objects.filter(
            room=chat_room,
            is_read=False
        ).exclude(sender=user).update(is_read=True)
        
        # Get messages
        messages = chat_room.messages.all().order_by('created_at')
        
        # Format messages
        formatted_messages = []
        for message in messages:
            formatted_messages.append({
                "id": message.id,
                "content": message.content,
                "message_type": message.message_type,
                "sender": {
                    "id": message.sender.id if message.sender else None,
                    "username": message.sender.username if message.sender else None,
                    "name": message.sender.get_full_name() if message.sender else None,
                    "role": message.sender.role if message.sender else None
                },
                "image_file": message.image_file.url if message.image_file else None,
                "audio_file": message.audio_file.url if message.audio_file else None,
                "video_file": message.video_file.url if message.video_file else None,
                "file": message.file.url if message.file else None,
                "file_name": message.file_name,
                "file_size": message.file_size,
                "duration": message.duration,
                "is_read": message.is_read,
                "created_at": message.created_at,
                "is_own": message.sender == user
            })
        
        return Response({
            'room_id': chat_room.id,
            'messages': formatted_messages,
            'total_messages': messages.count()
        })
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def librarian_send_message(request):
    """Librarian sends a message in a chat room"""
    room_id = request.data.get('room_id')
    content = request.data.get('content')
    
    if not room_id or not content:
        return Response({"error": "room_id and content required"}, status=400)
    
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        librarian = request.user
        
        # Check if librarian is a participant
        if librarian not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Create message
        message = Message.objects.create(
            room=chat_room,
            sender=librarian,
            content=content
        )
        
        # Update room's last message time
        chat_room.last_message_time = message.created_at
        chat_room.save()
        
        # Create notification for student
        student = chat_room.student
        if student:
            Notification.objects.create(
                user=student,
                title=f"New message from Librarian",
                message=content[:100],
                clearance_form=None
            )
        
        return Response({
            "message": "Message sent successfully",
            "message_id": message.id,
            "created_at": message.created_at
        }, status=201)
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def librarian_send_file_message(request):
    """Librarian sends a file in a chat room"""
    room_id = request.data.get('room_id')
    file = request.FILES.get('file')
    
    if not room_id or not file:
        return Response({"error": "room_id and file required"}, status=400)
    
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        librarian = request.user
        
        # Check if librarian is a participant
        if librarian not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Validate file size (10MB max)
        if file.size > 10 * 1024 * 1024:
            return Response({"error": "File size must be less than 10MB"}, status=400)
        
        # Create message with file
        message = Message.objects.create(
            room=chat_room,
            sender=librarian,
            content=f"File: {file.name}",
            file=file
        )
        
        # Update room's last message time
        chat_room.last_message_time = message.created_at
        chat_room.save()
        
        # Create notification for student
        student = chat_room.student
        if student:
            Notification.objects.create(
                user=student,
                title=f"New file from Librarian",
                message=f"File: {file.name}",
                clearance_form=None
            )
        
        return Response({
            "message": "File sent successfully",
            "message_id": message.id,
            "file_url": message.file.url,
            "file_name": file.name,
            "created_at": message.created_at
        }, status=201)
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def librarian_start_chat(request):
    """Librarian starts a chat with a student"""
    if request.user.role != "librarian":
        return Response({"error": "Unauthorized - Librarian only"}, status=403)
    
    student_id = request.data.get('student_id')
    if not student_id:
        return Response({"error": "Student ID required"}, status=400)
    
    try:
        student = User.objects.get(id=student_id, role='student')
        librarian = request.user
        
        # Check if chat already exists
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=librarian,
            room_type='student_librarian',
            is_active=True
        ).first()
        
        if existing_chat:
            return Response({
                "message": "Chat already exists",
                "chat_room": {
                    "id": existing_chat.id,
                    "name": existing_chat.name,
                    "student_name": student.get_full_name()
                }
            })
        
        # Create new chat room
        room_name = f"Library Chat - {student.get_full_name()}"
        
        chat_room = ChatRoom.objects.create(
            name=room_name,
            room_type='student_librarian',
            student=student,
            specific_staff=librarian,
            is_active=True
        )
        
        # Add participants
        chat_room.participants.add(student, librarian)
        
        # Create welcome message
        welcome_message = Message.objects.create(
            room=chat_room,
            sender=librarian,
            content=f"Hello {student.get_full_name()}! This is {librarian.get_full_name()} from Library department. How can I help you with your clearance?"
        )
        
        # Update last message time
        chat_room.last_message_time = welcome_message.created_at
        chat_room.save()
        
        # Create notification for student
        Notification.objects.create(
            user=student,
            message=f"Library staff {librarian.get_full_name()} started a chat with you",
            clearance_form=None
        )
        
        return Response({
            "message": "Chat started successfully",
            "chat_room": {
                "id": chat_room.id,
                "name": chat_room.name,
                "student": {
                    "id": student.id,
                    "name": student.get_full_name(),
                    "email": student.email
                },
                "staff": {
                    "id": librarian.id,
                    "name": librarian.get_full_name()
                }
            }
        }, status=201)
        
    except User.DoesNotExist:
        return Response({"error": "Student not found"}, status=404)
    except Exception as e:
        return Response({"error": f"Failed to start chat: {str(e)}"}, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def librarian_mark_messages_read(request):
    """Mark all messages in a room as read"""
    room_id = request.data.get('room_id')
    
    if not room_id:
        return Response({"error": "room_id is required"}, status=400)
    
    try:
        chat_room = ChatRoom.objects.get(id=room_id)
        librarian = request.user
        
        # Check if librarian is a participant
        if librarian not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Mark all unread messages as read (excluding librarian's own messages)
        Message.objects.filter(
            room=chat_room,
            is_read=False
        ).exclude(sender=librarian).update(is_read=True)
        
        return Response({
            "message": "Messages marked as read",
            "room_id": room_id
        })
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def librarian_get_students(request):
    """Get students for librarian to chat with"""
    if request.user.role != "librarian":
        return Response({"error": "Unauthorized - Librarian only"}, status=403)
    
    librarian = request.user
    
    # Get all clearance forms that are pending library check
    forms = ClearanceForm.objects.filter(
        status__in=['approved_department', 'requires_library_payment']
    )
    
    # Get unique students from these forms
    student_ids = set()
    students_list = []
    
    for form in forms:
        if form.student and form.student.id not in student_ids:
            student_ids.add(form.student.id)
            
            # Check if there's an existing chat
            existing_chat = ChatRoom.objects.filter(
                student=form.student,
                specific_staff=librarian,
                is_active=True,
                room_type='student_librarian'
            ).first()
            
            students_list.append({
                'id': form.student.id,
                'name': form.student.get_full_name(),
                'username': form.student.username,
                'email': form.student.email,
                'id_number': form.id_number,
                'department': form.department_name,
                'form_status': form.status,
                'has_existing_chat': existing_chat is not None,
                'chat_room_id': existing_chat.id if existing_chat else None,
                'last_chat': existing_chat.last_message_time if existing_chat else None
            })
    
    return Response({
        'role': 'librarian',
        'staff_name': librarian.get_full_name(),
        'total_students': len(students_list),
        'students': students_list
    })
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def check_student_books(request, student_id):
    """Check student's book status for librarian"""
    if request.user.role != "librarian":
        return Response({"error": "Unauthorized - Librarian access only"}, status=403)
    
    # This is the same as check_student_book_status but renamed
    try:
        # Find student by ID or ID number
        student = None
        
        # Try by numeric ID
        if student_id.isdigit():
            try:
                student = User.objects.get(id=int(student_id), role="student")
            except User.DoesNotExist:
                pass
        
        # If not found by ID, try by ID number
        if not student:
            try:
                student = User.objects.get(id_number=student_id, role="student")
            except User.DoesNotExist:
                pass
        
        if not student:
            return Response({"error": "Student not found"}, status=404)
        
        # Check book status using helper function
        book_status = check_student_book_status(student_id)
        
        if not book_status:
            return Response({"error": "Could not check book status"}, status=500)
        
        # Add student info to response
        book_status.update({
            "student_id": student.id,
            "student_name": student.get_full_name() or student.username,
            "id_number": student.id_number if hasattr(student, 'id_number') else student_id,
            "email": student.email
        })
        
        return Response(book_status)

    except Exception as e:
        print(f"Error checking student books: {e}")
        return Response({"error": str(e)}, status=500)


# ==================== PAYMENT METHOD VIEWS ====================
@api_view(['GET'])
@permission_classes([AllowAny])
def get_payment_methods(request):
    """Get active payment methods (public access)"""
    payment_methods = PaymentMethod.objects.filter(is_active=True)
    serializer = PaymentMethodSerializer(payment_methods, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_university_accounts(request):
    """Get university default accounts for payment methods"""
    payment_methods = PaymentMethod.objects.filter(is_active=True)
    
    university_accounts = {}
    for method in payment_methods:
        university_accounts[method.name.lower().replace(' ', '_')] = {
            'name': method.name,
            'phone_number': method.phone_number,
            'account_number': method.account_number,
            'account_name': method.account_name,
            'instructions': method.instructions.split('\n') if method.instructions else []
        }
    
    return Response(university_accounts)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def submit_payment(request):
    """Student submits a payment with receipt"""
    if request.user.role != 'student':
        return Response({"error": "Only students can submit payments"}, status=403)

    try:
        # ===================== FILE =====================
        receipt_file = request.FILES.get('receipt_file')
        if not receipt_file:
            return Response({"error": "Receipt file is required"}, status=400)

        allowed_extensions = ['.jpg', '.jpeg', '.png', '.pdf']
        file_ext = os.path.splitext(receipt_file.name)[1].lower()

        if file_ext not in allowed_extensions:
            return Response({
                "error": f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
            }, status=400)

        if receipt_file.size > 10 * 1024 * 1024:
            return Response({"error": "File must be under 10MB"}, status=400)

        # ===================== DATA =====================
        payment_method_id = request.data.get('payment_method_id')
        department_type = request.data.get('department_type')
        transaction_id = request.data.get('transaction_id')
        amount = request.data.get('amount')
        payment_date_str = request.data.get('payment_date')
        phone_number = request.data.get('phone_number', '')
        clearance_form_id = request.data.get('clearance_form_id')
        account_last_digits = request.data.get('account_last_digits', '')
        note = request.data.get('note', '')

        # ===================== VALIDATION =====================
        required_fields = {
            "payment_method_id": payment_method_id,
            "department_type": department_type,
            "transaction_id": transaction_id,
            "amount": amount,
            "payment_date": payment_date_str
        }

        missing = [k for k, v in required_fields.items() if not v]
        if missing:
            return Response({"error": f"Missing required fields: {', '.join(missing)}"}, status=400)

        try:
            payment_method = PaymentMethod.objects.get(id=payment_method_id)
        except PaymentMethod.DoesNotExist:
            return Response({"error": "Invalid payment method"}, status=400)

        if StudentPayment.objects.filter(transaction_id=transaction_id).exists():
            return Response({"error": "Transaction ID already exists"}, status=400)

        try:
            payment_date = datetime.strptime(payment_date_str, "%Y-%m-%d").date()
        except ValueError:
            return Response({"error": "Invalid date format. Use YYYY-MM-DD"}, status=400)
            
        # Validate clearance form if provided
        clearance_form = None
        if clearance_form_id:
            try:
                clearance_form = ClearanceForm.objects.get(
                    id=clearance_form_id,
                    student=request.user
                )
                
                # Check if this form actually requires payment for this department
                required_status_map = {
                    'library': 'requires_library_payment',
                    'cafeteria': 'requires_cafeteria_payment',
                    'dormitory': 'requires_dormitory_payment'
                }
                
                required_status = required_status_map.get(department_type)
                if required_status and clearance_form.status != required_status:
                    return Response({
                        "error": f"This form doesn't require {department_type} payment. Current status: {clearance_form.status}"
                    }, status=400)
                    
            except ClearanceForm.DoesNotExist:
                return Response({"error": "Clearance form not found or access denied"}, status=404)

        # ===================== CREATE =====================
        payment = StudentPayment.objects.create(
            student=request.user,
            clearance_form=clearance_form,
            payment_method=payment_method,
            department_type=department_type,
            transaction_id=transaction_id,
            amount=float(amount),
            receipt_file=receipt_file,
            phone_number=phone_number,
            account_last_digits=account_last_digits,
            note=note,
            payment_date=payment_date,
            status="pending"
        )

        if file_ext in ['.jpg', '.jpeg', '.png']:
            payment.generate_thumbnail()
            payment.save()

        # ===================== NOTIFICATIONS =====================
        department_roles = {
            "library": "librarian",
            "cafeteria": "cafeteria",
            "dormitory": "dormitory"
        }

        role = department_roles.get(department_type)
        if role:
            staff_users = User.objects.filter(role=role, is_active=True)
            for staff in staff_users:
                Notification.objects.create(
                    user=staff,
                    message=(f"New payment submitted by {request.user.username} | "
                             f"Form #{clearance_form.id if clearance_form else 'N/A'} | "
                             f"Department: {department_type} | "
                             f"Amount: {amount} ETB | "
                             f"Transaction: {transaction_id}")
                )

        Notification.objects.create(
            user=request.user,
            message=(f"Your payment of {payment.amount} ETB was submitted successfully. "
                     f"Waiting for {payment.department_type} verification.")
        )

        return Response({
            "message": "Payment submitted successfully",
            "payment_id": payment.id,
            "transaction_id": payment.transaction_id,
            "status": payment.status,
            "receipt_url": payment.receipt_file.url,
            "linked_form_id": payment.clearance_form.id if payment.clearance_form else None
        }, status=201)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"error": f"Payment submission failed: {str(e)}"}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_payment_status(request, payment_id):
    """Get detailed status of a payment"""
    try:
        payment = StudentPayment.objects.get(id=payment_id)
        
        # Check permissions
        if request.user.role == 'student' and payment.student != request.user:
            return Response({"error": "Unauthorized"}, status=403)
        
        if request.user.role in ['librarian', 'cafeteria', 'dormitory']:
            # Staff can only see payments for their department
            department_map = {
                'librarian': 'library',
                'cafeteria': 'cafeteria',
                'dormitory': 'dormitory'
            }
            if payment.department_type != department_map.get(request.user.role):
                return Response({"error": "Unauthorized - Wrong department"}, status=403)
        
        serializer = StudentPaymentSerializer(payment)
        return Response(serializer.data)
        
    except StudentPayment.DoesNotExist:
        return Response({"error": "Payment not found"}, status=404)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_form_payment_status(request, form_id):
    """Check if a form requires payment and get payment details"""
    try:
        form = get_object_or_404(ClearanceForm, id=form_id)
        
        # Check permissions
        if request.user.role == 'student' and form.student != request.user:
            return Response({"error": "Unauthorized"}, status=403)
        
        # Determine which department requires payment
        payment_required = False
        required_department = None
        rejection_note = None
        payment_amount = None
        
        if form.status == 'requires_library_payment':
            payment_required = True
            required_department = 'library'
            rejection_note = form.library_note
            # Extract amount from note if available
            if form.library_note:
                import re
                amount_match = re.search(r'Payment required:\s*(\d+)\s*ETB', form.library_note, re.IGNORECASE)
                if amount_match:
                    payment_amount = amount_match.group(1)
                    
        elif form.status == 'requires_cafeteria_payment':
            payment_required = True
            required_department = 'cafeteria'
            rejection_note = form.cafeteria_note
            
        elif form.status == 'requires_dormitory_payment':
            payment_required = True
            required_department = 'dormitory'
            rejection_note = form.dormitory_note
        
        # Check if payment already exists
        existing_payment = None
        if payment_required:
            existing_payment = StudentPayment.objects.filter(
                student=form.student,
                clearance_form=form,
                department_type=required_department,
                status='verified'
            ).order_by('-created_at').first()
        
        # Generate payment link
        payment_link = None
        if payment_required and not existing_payment:
            base_url = "http://127.0.0.1:3000"  # Update with your frontend URL
            payment_link = f"{base_url}/student/payments?form_id={form.id}&department={required_department}"
            if payment_amount:
                payment_link += f"&amount={payment_amount}"
            if rejection_note:
                import urllib.parse
                encoded_note = urllib.parse.quote(rejection_note[:100])
                payment_link += f"&reason={encoded_note}"
        
        return Response({
            'form_id': form.id,
            'form_status': form.status,
            'payment_required': payment_required,
            'required_department': required_department,
            'rejection_note': rejection_note,
            'payment_amount': payment_amount,
            'payment_link': payment_link,
            'has_verified_payment': existing_payment is not None,
            'verification_info': {
                'id': existing_payment.id if existing_payment else None,
                'transaction_id': existing_payment.transaction_id if existing_payment else None,
                'amount': str(existing_payment.amount) if existing_payment else None,
                'verified_at': existing_payment.verified_at if existing_payment else None,
                'verified_by': existing_payment.verified_by.username if existing_payment and existing_payment.verified_by else None
            } if existing_payment else None
        })
        
    except ClearanceForm.DoesNotExist:
        return Response({"error": "Form not found"}, status=404)

# ==================== PAYMENT METHODS CRUD ====================
# Add this to your views.py in the payment method section:

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def payment_methods_list(request):
    """Admin: Get all payment methods or create new one"""
    if request.method == 'GET':
        payment_methods = PaymentMethod.objects.all().order_by('name')
        serializer = PaymentMethodSerializer(payment_methods, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = PaymentMethodSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Payment method created successfully",
                "data": serializer.data
            }, status=201)
        return Response(serializer.errors, status=400)


@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def payment_method_detail(request, pk):
    """Admin: CRUD operations for specific payment method"""
    try:
        payment_method = PaymentMethod.objects.get(pk=pk)
    except PaymentMethod.DoesNotExist:
        return Response({'error': 'Payment method not found'}, status=404)
    
    if request.method == 'GET':
        serializer = PaymentMethodSerializer(payment_method)
        return Response(serializer.data)
    
    elif request.method == 'PUT' or request.method == 'PATCH':
        serializer = PaymentMethodSerializer(payment_method, data=request.data, partial=(request.method == 'PATCH'))
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Payment method updated successfully",
                "data": serializer.data
            })
        return Response(serializer.errors, status=400)
    
    elif request.method == 'DELETE':
        # Check if any payments are using this method
        if StudentPayment.objects.filter(payment_method=payment_method).exists():
            return Response({
                "error": "Cannot delete payment method. It is being used by existing payments."
            }, status=400)
        
        payment_method.delete()
        return Response({"message": "Payment method deleted successfully"}, status=204)
# ==================== STAFF VERIFICATION VIEWS ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_payments(request):
    """Get pending payments for staff verification"""
    # Determine department based on user role
    department_map = {
        'librarian': 'library',
        'cafeteria': 'cafeteria',
        'dormitory': 'dormitory'
    }
    
    department = department_map.get(request.user.role)
    if not department:
        return Response({"error": "Unauthorized - Not a verification staff"}, status=403)
    
    # Get pending payments for this department
    payments = StudentPayment.objects.filter(
        department_type=department,
        status='pending'
    ).order_by('-created_at')
    
    serializer = StudentPaymentSerializer(payments, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_verified_payments(request):
    """Get verified payments for staff"""
    department_map = {
        'librarian': 'library',
        'cafeteria': 'cafeteria',
        'dormitory': 'dormitory'
    }
    
    department = department_map.get(request.user.role)
    if not department:
        return Response({"error": "Unauthorized - Not a verification staff"}, status=403)
    
    payments = StudentPayment.objects.filter(
        department_type=department,
        status__in=['verified', 'rejected']
    ).order_by('-verified_at')
    
    serializer = StudentPaymentSerializer(payments, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_payment(request, payment_id):
    """Verify or reject a payment AND auto-update clearance form"""
    try:
        payment = StudentPayment.objects.get(id=payment_id)
        
        # Check if user can verify this payment
        department_map = {
            'librarian': 'library',
            'cafeteria': 'cafeteria',
            'psychology': 'psychology',
            'sportmaster': 'sportmaster',
            'campuspolice': 'campuspolice',
            'cooperationsharing': 'cooperationsharing',
            'dopcordinator': 'dopcordinator',
            'studentaffairs': 'studentaffairs',
            'dormitory': 'dormitory'
        }
        
        department = department_map.get(request.user.role)
        if not department or payment.department_type != department:
            return Response({"error": "Unauthorized - Wrong department"}, status=403)
        
        if payment.status != 'pending':
            return Response({"error": f"Payment is already {payment.status}"}, status=400)
        
        serializer = PaymentVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
        
        data = serializer.validated_data
        action = data['action']
        note = data.get('note', '')
        
        with transaction.atomic():
            if action == 'verify':
                payment.status = 'verified'
                payment.verified_by = request.user
                payment.verified_at = timezone.now()
                payment.rejection_reason = None
                
                # Create verification log
                PaymentVerificationLog.objects.create(
                    payment=payment,
                    verified_by=request.user,
                    action='verify',
                    note=note or 'Payment verified'
                )

                # Notify student
                Notification.objects.create(
                    user=payment.student,
                    message=f"Your payment of {payment.amount} ETB has been VERIFIED by {request.user.get_full_name() or request.user.username} ({request.user.role}). Transaction ID: {payment.transaction_id}"
                )
                
                # ============ AUTO-UPDATE CLEARANCE FORM ============
                auto_update_clearance_form(payment)
                
                message_text = "Payment verified and clearance form updated"
                
            else:  # reject
                payment.status = 'rejected'
                payment.verified_by = request.user
                payment.verified_at = timezone.now()
                payment.rejection_reason = note
                
                # Create verification log
                PaymentVerificationLog.objects.create(
                    payment=payment,
                    verified_by=request.user,
                    action='reject',
                    note=note
                )
                
                # Notify student
                Notification.objects.create(
                    user=payment.student,
                    message=f"Your payment of {payment.amount} ETB has been REJECTED by {request.user.get_full_name() or request.user.username} ({request.user.role}). Reason: {note}. Transaction ID: {payment.transaction_id}"
                )
                
                message_text = "Payment rejected"
            
            payment.save()
            
            # Prepare response data
            response_data = {
                "message": message_text,
                "payment_id": payment.id,
                "status": payment.status,
                "verified_by": {
                    "username": request.user.username,
                    "full_name": request.user.get_full_name(),
                    "role": request.user.role
                },
                "verified_at": payment.verified_at,
                "rejection_reason": payment.rejection_reason if payment.status == 'rejected' else None,
                "clearance_updated": action == 'verify'
            }
            
            return Response(response_data, status=200)
            
    except StudentPayment.DoesNotExist:
        return Response({"error": "Payment not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


def auto_update_clearance_form(payment):
    """Automatically update clearance form after payment verification"""
    try:
        student = payment.student
        department_type = payment.department_type
        verified_by = payment.verified_by
        
        # Map payment department to clearance form fields
        department_status_map = {
            'library': {
                'status_field': 'requires_library_payment',
                'next_status': 'approved_library',
                'note_field': 'library_note',
                'approved_by_field': 'library_approved_by',
                'role_name': 'Librarian'
            },
            'cafeteria': {
                'status_field': 'requires_cafeteria_payment',
                'next_status': 'approved_cafeteria',
                'note_field': 'cafeteria_note',
                'approved_by_field': 'cafeteria_approved_by',
                'role_name': 'Cafeteria Manager'
            },
            'psychology': {
                'status_field': 'requires_psychology_payment',
                'next_status': 'approved_psychology',
                'note_field': 'psychology_note',
                'approved_by_field': 'psychology_approved_by',
                'role_name': 'Psychology'
            },
            'sportmaster': {
                'status_field': 'requires_sportmaster_payment',
                'next_status': 'approved_sportmaster',
                'note_field': 'sportmaster_note',
                'approved_by_field': 'sportmaster_approved_by',
                'role_name': 'Sport Master'
            },
            'campuspolice': {
                'status_field': 'requires_campuspolice_payment',
                'next_status': 'approved_campuspolice',
                'note_field': 'campuspolice_note',
                'approved_by_field': 'campuspolice_approved_by',
                'role_name': 'Campus Police'
            },
            'cooperationsharing': {
                'status_field': 'requires_cooperationsharing_payment',
                'next_status': 'approved_cooperationsharing',
                'note_field': 'cooperationsharing_note',
                'approved_by_field': 'cooperationsharing_approved_by',
                'role_name': 'Cooperation Sharing'
            },
            'dopcordinator': {
                'status_field': 'requires_dopcordinator_payment',
                'next_status': 'approved_dopcordinator',
                'note_field': 'dopcordinator_note',
                'approved_by_field': 'dopcordinator_approved_by',
                'role_name': 'DOP Cordinator'
            },
            'studentaffairs': {
                'status_field': 'requires_studentaffairs_payment',
                'next_status': 'approved_studentaffairs',
                'note_field': 'studentaffairs_note',
                'approved_by_field': 'studentaffairs_approved_by',
                'role_name': 'Student Affairs'
            },
            'dormitory': {
                'status_field': 'requires_dormitory_payment',
                'next_status': 'approved_dormitory',
                'note_field': 'dormitory_note',
                'approved_by_field': 'dormitory_approved_by',
                'role_name': 'Dormitory Manager'
            }
        }
        
        dept_info = department_status_map.get(department_type)
        if not dept_info:
            print(f"ERROR: No department info for {department_type}")
            return False
        
        # Find forms that need payment for this department
        forms = ClearanceForm.objects.filter(
            student=student,
            status=dept_info['status_field']
        ).order_by('-created_at')
        
        if not forms.exists():
            # Check alternative status if payment is made proactively
            alt_status_map = {
                'library': 'approved_department',
                'cafeteria': 'approved_library',
                'psychology': 'approved_cafeteria',
                'sportmaster': 'approved_psychology',
                'campuspolice': 'approved_sportmaster',
                'cooperationsharing': 'approved_campuspolice',
                'dopcordinator': 'approved_cooperationsharing',
                'studentaffairs': 'approved_dopcordinator',
                'dormitory': 'approved_studentaffairs'
            }
            alt_status = alt_status_map.get(department_type)
            if alt_status:
                forms = ClearanceForm.objects.filter(
                    student=student,
                    status=alt_status
                ).order_by('-created_at')
        
        if not forms.exists():
            print(f"ERROR: No forms found for student {student.id} with department {department_type}")
            return False
        
        # Update the latest form
        form = forms.first()
        print(f"Updating form #{form.id} for {department_type} payment")
        
        # Create approval name with role
        if verified_by:
            staff_name = verified_by.get_full_name() or verified_by.username
            approval_name = f"{staff_name} ({dept_info['role_name']})"
        else:
            approval_name = f"System ({dept_info['role_name']})"
        
        print(f"Setting approval name: '{approval_name}' for field: {dept_info['approved_by_field']}")
        
        # Update form status and approval fields
        form.status = dept_info['next_status']
        
        # Set the approved_by field
        if hasattr(form, dept_info['approved_by_field']):
            setattr(form, dept_info['approved_by_field'], approval_name)
            print(f"✓ Set {dept_info['approved_by_field']} = {approval_name}")
        else:
            print(f"✗ Field {dept_info['approved_by_field']} does not exist on form")
        
        # Set the note
        setattr(form, dept_info['note_field'], 
                f"Payment verified. Transaction: {payment.transaction_id} | Amount: {payment.amount} ETB")
        
        form.updated_at = timezone.now()
        form.save()
        
        # Verify the field was saved
        updated_form = ClearanceForm.objects.get(id=form.id)
        saved_value = getattr(updated_form, dept_info['approved_by_field'], None)
        print(f"Verification - saved value: '{saved_value}'")
        
        # Create notification for student
        Notification.objects.create(
            user=student,
            message=f"✅ Your clearance form #{form.id} has been approved by {dept_info['role_name']} after payment verification.",
            clearance_form=form,
            notification_type="success"
        )
        
        # Send notification to next department
        send_next_department_notification(form)
        
        return True
        
    except Exception as e:
        print(f"Error in auto_update_clearance_form: {e}")
        import traceback
        traceback.print_exc()
        return False


def send_next_department_notification(form):
    """Send notification to next department after approval"""
    try:
        # Map current status to next department
        next_dept_map = {
            'approved_department': ('librarian', 'Library'),
            'approved_library': ('cafeteria', 'Cafeteria'),
            'approved_cafeteria': ('psychology', 'Psychology'),
            'approved_psychology': ('sportmaster', 'Sport Master'),
            'approved_sportmaster': ('campuspolice', 'Campus Police'),
            'approved_campuspolice': ('cooperationsharing', 'Cooperation Sharing'),
            'approved_cooperationsharing': ('dopcordinator', 'DOP Cordinator'),
            'approved_dopcordinator': ('studentaffairs', 'Student Affairs'),
            'approved_studentaffairs': ('dormitory', 'Dormitory'),
            'approved_dormitory': ('registrar', 'Registrar')
        }
        
        next_info = next_dept_map.get(form.status)
        if next_info:
            role, dept_name = next_info
            staff_users = User.objects.filter(role=role, is_active=True)
            for staff in staff_users:
                Notification.objects.create(
                    user=staff,
                    message=f"📋 New clearance form #{form.id} from {form.student.username if form.student else form.full_name} ready for {dept_name} review",
                    notification_type="info",
                    clearance_form=form
                )
            print(f"✓ Notified {staff_users.count()} {role}(s) about form #{form.id}")
        
    except Exception as e:
        print(f"Error in send_next_department_notification: {e}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_payment_verification_logs(request, payment_id):
    """Get verification logs for a payment"""
    try:
        payment = StudentPayment.objects.get(id=payment_id)
        
        # Check permissions
        if request.user.role == 'student' and payment.student != request.user:
            return Response({"error": "Unauthorized"}, status=403)
        
        if request.user.role in ['librarian', 'cafeteria', 'dormitory']:
            department_map = {
                'librarian': 'library',
                'cafeteria': 'cafeteria',
                'dormitory': 'dormitory'
            }
            if payment.department_type != department_map.get(request.user.role):
                return Response({"error": "Unauthorized - Wrong department"}, status=403)
        
        logs = PaymentVerificationLog.objects.filter(payment=payment).order_by('-created_at')
        serializer = PaymentVerificationLogSerializer(logs, many=True)
        return Response(serializer.data)
        
    except StudentPayment.DoesNotExist:
        return Response({"error": "Payment not found"}, status=404)


# ==================== ADMIN PAYMENT MANAGEMENT ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def get_all_payments(request):
    """Admin: Get all payments"""
    payments = StudentPayment.objects.all().order_by('-created_at')
    serializer = StudentPaymentSerializer(payments, many=True)
    return Response(serializer.data)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def admin_update_payment(request, payment_id):
    """Admin: Update payment status"""
    try:
        payment = StudentPayment.objects.get(id=payment_id)
        
        new_status = request.data.get('status')
        if new_status not in ['pending', 'verified', 'rejected', 'expired']:
            return Response({"error": "Invalid status"}, status=400)
        
        payment.status = new_status
        if 'rejection_reason' in request.data:
            payment.rejection_reason = request.data['rejection_reason']
        
        payment.save()
        
        # Create log
        PaymentVerificationLog.objects.create(
            payment=payment,
            verified_by=request.user,
            action='verify' if new_status == 'verified' else 'reject',
            note=f"Admin update: {request.data.get('note', '')}"
        )
        
        return Response({
            "message": f"Payment status updated to {new_status}",
            "payment": StudentPaymentSerializer(payment).data
        })
        
    except StudentPayment.DoesNotExist:
        return Response({"error": "Payment not found"}, status=404)


# ==================== PAYMENT STATISTICS ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_student_payments(request):
    """Get payments for current student"""
    if request.user.role != 'student':
        return Response({"error": "Only students can view their payments"}, status=403)
    
    payments = StudentPayment.objects.filter(student=request.user).order_by('-created_at')
    serializer = StudentPaymentSerializer(payments, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def payment_statistics(request):
    """Get payment statistics"""
    user = request.user
    stats = {}
    
    try:
        if user.role == 'student':
            payments = StudentPayment.objects.filter(student=user)
            stats = {
                'total_payments': payments.count(),
                'total_amount': payments.aggregate(Sum('amount'))['amount__sum'] or 0,
                'pending': payments.filter(status='pending').count(),
                'verified': payments.filter(status='verified').count(),
                'rejected': payments.filter(status='rejected').count(),
            }
            
        elif user.role in ['librarian', 'cafeteria', 'dormitory']:
            department_map = {
                'librarian': 'library',
                'cafeteria': 'cafeteria',
                'dormitory': 'dormitory'
            }
            
            department = department_map.get(user.role)
            if not department:
                return Response({"error": "Unauthorized - Not a verification staff"}, status=403)
            
            payments = StudentPayment.objects.filter(department_type=department)
            stats = {
                'total_payments': payments.count(),
                'total_amount': payments.aggregate(Sum('amount'))['amount__sum'] or 0,
                'pending': payments.filter(status='pending').count(),
                'verified': payments.filter(status='verified').count(),
                'rejected': payments.filter(status='rejected').count(),
                'today_pending': payments.filter(
                    status='pending',
                    created_at__date=timezone.now().date()
                ).count(),
                'weekly_pending': payments.filter(
                    status='pending',
                    created_at__gte=timezone.now() - timedelta(days=7)
                ).count(),
            }
            
        elif user.role == 'admin':
            # Calculate department statistics
            library_count = StudentPayment.objects.filter(department_type='library').count()
            cafeteria_count = StudentPayment.objects.filter(department_type='cafeteria').count()
            dormitory_count = StudentPayment.objects.filter(department_type='dormitory').count()
            other_count = StudentPayment.objects.filter(department_type='other').count()
            
            stats = {
                'total_payments': StudentPayment.objects.count(),
                'total_amount': StudentPayment.objects.aggregate(Sum('amount'))['amount__sum'] or 0,
                'pending': StudentPayment.objects.filter(status='pending').count(),
                'verified': StudentPayment.objects.filter(status='verified').count(),
                'rejected': StudentPayment.objects.filter(status='rejected').count(),
                'by_department': {
                    'library': library_count,
                    'cafeteria': cafeteria_count,
                    'dormitory': dormitory_count,
                    'other': other_count,
                }
            }
        
        # Add user info to stats for debugging
        stats['user_role'] = user.role
        stats['user_id'] = user.id
        
        return Response(stats)
        
    except Exception as e:
        print(f"Error in payment_statistics: {str(e)}")
        return Response({"error": f"Error getting statistics: {str(e)}"}, status=500)


# ==================== RECEIPT VIEW ====================
from django.http import FileResponse

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def view_receipt(request, payment_id):
    """View payment receipt"""
    try:
        payment = StudentPayment.objects.get(id=payment_id)
        
        # Check permissions
        if request.user.role == 'student' and payment.student != request.user:
            return Response({"error": "Unauthorized"}, status=403)
        
        if request.user.role in ['librarian', 'cafeteria', 'dormitory']:
            department_map = {
                'librarian': 'library',
                'cafeteria': 'cafeteria',
                'dormitory': 'dormitory'
            }
            if payment.department_type != department_map.get(request.user.role):
                return Response({"error": "Unauthorized - Wrong department"}, status=403)
        
        # Return file response
        if payment.receipt_file and os.path.exists(payment.receipt_file.path):
            return FileResponse(
                payment.receipt_file.open(),
                content_type='image/jpeg'
            )
        else:
            return Response({"error": "Receipt file not found"}, status=404)
            
    except StudentPayment.DoesNotExist:
        return Response({"error": "Payment not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ==================== PAYMENT METHODS CRUD ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def get_all_payment_methods_admin(request):
    """Admin: Get all payment methods (including inactive)"""
    payment_methods = PaymentMethod.objects.all().order_by('name')
    serializer = PaymentMethodSerializer(payment_methods, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def create_payment_method(request):
    """Admin: Create a new payment method"""
    serializer = PaymentMethodSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({
            "message": "Payment method created successfully",
            "data": serializer.data
        }, status=201)
    return Response(serializer.errors, status=400)

@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def update_payment_method(request, method_id):
    """Admin: Update a payment method"""
    try:
        payment_method = PaymentMethod.objects.get(id=method_id)
    except PaymentMethod.DoesNotExist:
        return Response({"error": "Payment method not found"}, status=404)
    
    serializer = PaymentMethodSerializer(payment_method, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({
            "message": "Payment method updated successfully",
            "data": serializer.data
        })
    return Response(serializer.errors, status=400)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def delete_payment_method(request, method_id):
    """Admin: Delete a payment method"""
    try:
        payment_method = PaymentMethod.objects.get(id=method_id)
        
        # Check if any payments are using this method
        if StudentPayment.objects.filter(payment_method=payment_method).exists():
            return Response({
                "error": "Cannot delete payment method. It is being used by existing payments."
            }, status=400)
        
        payment_method.delete()
        return Response({"message": "Payment method deleted successfully"})
        
    except PaymentMethod.DoesNotExist:
        return Response({"error": "Payment method not found"}, status=404)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def toggle_payment_method_status(request, method_id):
    """Admin: Toggle payment method active status"""
    try:
        payment_method = PaymentMethod.objects.get(id=method_id)
        payment_method.is_active = not payment_method.is_active
        payment_method.save()
        
        return Response({
            "message": f"Payment method {'activated' if payment_method.is_active else 'deactivated'}",
            "is_active": payment_method.is_active
        })
        
    except PaymentMethod.DoesNotExist:
        return Response({"error": "Payment method not found"}, status=404)

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def admin_get_all_payments(request):
    """Admin: Get all payments"""
    payments = StudentPayment.objects.all().select_related(
        'student', 'payment_method', 'verified_by'
    ).order_by('-created_at')
    serializer = StudentPaymentSerializer(payments, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([AllowAny])
def test_view(request):
    """Test endpoint to verify API is working"""
    return Response({"message": "API is working", "status": "OK"})
def system_closed(request):
    return render(request, 'system_closed.html', {'message': 'The system is currently closed. Only Admin can access.'})


@system_open_required
def student_dashboard(request):
    # Student dashboard logic
    return render(request, 'student_dashboard.html')

@system_open_required
def department_head_dashboard(request):
    return render(request, 'department_head_dashboard.html')

@system_open_required
def librarian_dashboard(request):
    return render(request, 'librarian_dashboard.html')

# etc. for Cafeteria, Dormitory, Registrar


@api_view(['GET', 'POST', 'PUT'])
@permission_classes([IsAuthenticated, IsAdminUserRole])
def system_control_detail(request):
    """Admin: Get or update system control settings"""
    try:
        # Try to get existing system control
        system_control = SystemControl.objects.first()
        
        if request.method == 'GET':
            if not system_control:
                # Return default values if no system control exists
                return Response({
                    "is_open": True,
                    "maintenance_title": "",
                    "maintenance_message": "",
                    "show_maintenance_page": True,
                    "is_department_head_open": True,
                    "is_librarian_open": True,
                    "is_cafeteria_open": True,
                    "is_dormitory_open": True,
                    "is_registrar_open": True,
                    "is_student_open": True,
                    "is_payment_open": True,
                    "scheduled_maintenance_start": None,
                    "scheduled_maintenance_end": None,
                    "scheduled_maintenance_message": "",
                })
            
            serializer = SystemControlSerializer(system_control)
            return Response(serializer.data)
        
        elif request.method in ['POST', 'PUT']:
            data = request.data.copy()
            
            # Ensure all required boolean fields are provided with defaults
            boolean_fields = [
                'is_open', 'show_maintenance_page',
                'is_department_head_open', 'is_librarian_open',
                'is_cafeteria_open', 'is_dormitory_open',
                'is_registrar_open', 'is_student_open',
                'is_payment_open'
            ]
            
            for field in boolean_fields:
                if field not in data:
                    data[field] = True
            
            if system_control:
                # Update existing
                serializer = SystemControlSerializer(system_control, data=data, partial=True)
            else:
                # Create new
                serializer = SystemControlSerializer(data=data)
            
            if serializer.is_valid():
                serializer.save()
                
                # Log the change
                if request.user:
                    action = "opened" if serializer.validated_data.get('is_open', False) else "closed"
                    Notification.objects.create(
                        user=request.user,
                        message=f"System control updated by {request.user.username}. System {action}.",
                        notification_type="system"
                    )
                
                return Response({
                    'message': 'System control updated successfully',
                    'system': serializer.data
                })
            return Response(serializer.errors, status=400)
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)



# In your views.py, add these new views

class CSVUploadView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]
    parser_classes = [MultiPartParser, FormParser]
    
    def post(self, request):
        """Upload CSV file with student data - FIXED VERSION"""
        try:
            csv_file = request.FILES.get('csv_file')
            
            if not csv_file:
                return Response({"error": "No CSV file provided"}, status=400)
            
            print(f"=== CSV UPLOAD STARTED ===")
            print(f"File: {csv_file.name}, Size: {csv_file.size}")
            
            # Read file content first for debugging
            csv_content = csv_file.read()
            print(f"Raw content length: {len(csv_content)} bytes")
            print(f"First 500 chars: {csv_content[:500]}")
            
            # Reset file pointer
            csv_file.seek(0)
            
            # Create CSV upload record
            csv_upload = CSVStudentUpload.objects.create(
                uploaded_by=request.user,
                file=csv_file,
                filename=csv_file.name
            )
            
            # Process CSV file
            try:
                import csv
                import io
                
                # Try different encodings
                encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
                
                csv_text = None
                for encoding in encodings:
                    try:
                        csv_file.seek(0)
                        csv_text = csv_file.read().decode(encoding)
                        print(f"Successfully decoded with {encoding}")
                        break
                    except UnicodeDecodeError as e:
                        print(f"Failed with {encoding}: {e}")
                        continue
                
                if csv_text is None:
                    raise ValueError("Could not decode CSV file")
                
                print(f"Decoded text length: {len(csv_text)}")
                print(f"First 500 chars of decoded:\n{csv_text[:500]}")
                
                csv_io = io.StringIO(csv_text)
                
                # Try different CSV dialects
                sniffer = csv.Sniffer()
                sample = csv_text[:1024]
                
                try:
                    dialect = sniffer.sniff(sample)
                    print(f"Detected CSV dialect: delimiter='{dialect.delimiter}', quotechar='{dialect.quotechar}'")
                except:
                    print("Could not detect CSV dialect, using default")
                    dialect = csv.excel
                
                csv_reader = csv.DictReader(csv_io, dialect=dialect)
                
                print(f"Fieldnames: {csv_reader.fieldnames}")
                
                if not csv_reader.fieldnames:
                    return Response({"error": "CSV file has no headers or is empty"}, status=400)
                
                # Show what headers were found
                print(f"Original headers: {csv_reader.fieldnames}")
                
                # Map column names (case insensitive, space insensitive)
                header_map = {}
                for header in csv_reader.fieldnames:
                    normalized = header.strip().lower().replace(' ', '_').replace('-', '_')
                    header_map[normalized] = header
                
                print(f"Normalized header map: {header_map}")
                
                required = ['first_name', 'last_name', 'id_number']
                missing = []
                for req in required:
                    if req not in header_map:
                        missing.append(req)
                
                if missing:
                    return Response({
                        "error": f"Missing required columns: {', '.join(missing)}",
                        "found_columns": csv_reader.fieldnames,
                        "suggestions": "Make sure your CSV has columns named: first_name, last_name, id_number (case insensitive)"
                    }, status=400)
                
                total_records = 0
                successful_records = 0
                failed_records = 0
                errors = []
                
                # Process each row
                for row_num, row in enumerate(csv_reader, start=2):
                    total_records += 1
                    
                    try:
                        # Get values using mapped headers
                        first_name = row.get(header_map['first_name'], '').strip()
                        last_name = row.get(header_map['last_name'], '').strip()
                        id_number = row.get(header_map['id_number'], '').strip()
                        
                        print(f"Row {row_num}: first_name='{first_name}', last_name='{last_name}', id_number='{id_number}'")
                        
                        # Validate
                        if not first_name:
                            raise ValueError("First name is empty")
                        if not last_name:
                            raise ValueError("Last name is empty")
                        if not id_number:
                            raise ValueError("ID number is empty")
                        
                        # Check for duplicates
                        if AuthorizedStudent.objects.filter(id_number=id_number).exists():
                            existing = AuthorizedStudent.objects.get(id_number=id_number)
                            raise ValueError(f"ID {id_number} already exists for {existing.first_name} {existing.last_name}")
                        
                        # Create student
                        student = AuthorizedStudent.objects.create(
                            csv_upload=csv_upload,
                            first_name=first_name,
                            last_name=last_name,
                            id_number=id_number,
                            is_active=True,
                            is_registered=False
                        )
                        
                        print(f"✓ Created student: {student.id} - {student.first_name} {student.last_name}")
                        successful_records += 1
                        
                    except Exception as e:
                        failed_records += 1
                        error_msg = f"Row {row_num}: {str(e)}"
                        errors.append(error_msg)
                        print(f"✗ {error_msg}")
                
                # Update upload record
                csv_upload.total_records = total_records
                csv_upload.successful_records = successful_records
                csv_upload.failed_records = failed_records
                csv_upload.save()
                
                print(f"=== PROCESSING COMPLETE ===")
                print(f"Total rows: {total_records}")
                print(f"Successful: {successful_records}")
                print(f"Failed: {failed_records}")
                
                return Response({
                    "message": "CSV processed successfully" if successful_records > 0 else "CSV processed with errors",
                    "summary": {
                        "total_records": total_records,
                        "successful": successful_records,
                        "failed": failed_records,
                        "upload_id": csv_upload.id
                    },
                    "errors": errors[:10] if errors else []
                }, status=201)
                
            except Exception as e:
                print(f"Error in CSV processing: {str(e)}")
                import traceback
                traceback.print_exc()
                csv_upload.delete()
                return Response({"error": f"CSV processing error: {str(e)}"}, status=400)
                
        except Exception as e:
            print(f"Error in CSV upload: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response({"error": str(e)}, status=500)


class AuthorizedStudentListView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]
    
    def get(self, request):
        """Get list of authorized students"""
        students = AuthorizedStudent.objects.all().select_related(
            'college', 'department', 'registered_user'
        ).order_by('-created_at')
        
        serializer = AuthorizedStudentSerializer(students, many=True)
        return Response(serializer.data)


class AuthorizedStudentDetailView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]
    
    def delete(self, request, student_id):
        """Delete an authorized student"""
        try:
            student = AuthorizedStudent.objects.get(id=student_id)
            
            # Don't delete if already registered
            if student.is_registered:
                return Response({
                    "error": "Cannot delete student that is already registered"
                }, status=400)
            
            student.delete()
            return Response({"message": "Student deleted successfully"})
            
        except AuthorizedStudent.DoesNotExist:
            return Response({"error": "Student not found"}, status=404)


class ToggleAuthorizedStudentView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]
    
    def patch(self, request, student_id):
        """Toggle student active status"""
        try:
            student = AuthorizedStudent.objects.get(id=student_id)
            student.is_active = not student.is_active
            student.save()
            
            return Response({
                "message": f"Student {'activated' if student.is_active else 'deactivated'}",
                "is_active": student.is_active
            })
            
        except AuthorizedStudent.DoesNotExist:
            return Response({"error": "Student not found"}, status=404)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_student_by_id(request):
    """Verify student by ID only and return their information"""
    try:
        id_number = request.data.get('id_number', '').strip()
        
        if not id_number:
            return Response({
                "error": "Student ID is required",
                "details": "Please enter your student ID"
            }, status=400)
        
        print(f"Looking for student with ID: {id_number}")
        
        # Find authorized student by ID only
        authorized_student = AuthorizedStudent.objects.filter(
            id_number=id_number,
            is_active=True,
            is_registered=False
        ).select_related('college', 'department').first()
        
        if authorized_student:
            print(f"Found student: {authorized_student.first_name} {authorized_student.last_name}")
            
            # Return student information
            return Response({
                "success": True,
                "message": "Student verified successfully",
                "student": {
                    "id": authorized_student.id,
                    "first_name": authorized_student.first_name,
                    "last_name": authorized_student.last_name,
                    "id_number": authorized_student.id_number,
                    "email": authorized_student.email,
                    "college": authorized_student.college.name if authorized_student.college else None,
                    "college_id": authorized_student.college.id if authorized_student.college else None,
                    "department": authorized_student.department.name if authorized_student.department else None,
                    "department_id": authorized_student.department.id if authorized_student.department else None,
                    "is_registered": authorized_student.is_registered,
                    "is_active": authorized_student.is_active,
                }
            })
        else:
            print(f"No student found with ID: {id_number}")
            
            # Check if student exists but is already registered
            registered_student = AuthorizedStudent.objects.filter(
                id_number=id_number,
                is_registered=True
            ).first()
            
            if registered_student:
                return Response({
                    "error": "Already registered",
                    "details": f"This student ID is already registered for {registered_student.first_name} {registered_student.last_name}",
                    "suggestions": "Please use the login page to access your account."
                }, status=400)
            
            # Check if student exists but inactive
            inactive_student = AuthorizedStudent.objects.filter(
                id_number=id_number,
                is_active=False
            ).exists()
            
            if inactive_student:
                return Response({
                    "error": "Account inactive",
                    "details": "This student account is not active",
                    "suggestions": "Contact your department administrator to activate your account."
                }, status=400)
            
            # No student found
            return Response({
                "error": "Student not found",
                "details": f"No student found with ID: {id_number}",
                "suggestions": "Please check your student ID and try again. If the problem persists, contact your department."
            }, status=404)
            
    except Exception as e:
        print(f"Error in verify_student_by_id: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return Response({
            "error": "Internal server error",
            "details": str(e),
            "suggestions": "Please try again later or contact support."
        }, status=500)

class CSVUploadListView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]
    
    def get(self, request):
        """Get list of CSV uploads"""
        uploads = CSVStudentUpload.objects.all().select_related('uploaded_by').order_by('-created_at')
        serializer = CSVUploadSerializer(uploads, many=True)
        return Response(serializer.data)


class CSVUploadDetailView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUserRole]
    
    def delete(self, request, upload_id):
        """Delete a CSV upload and associated students (only if not registered)"""
        try:
            csv_upload = CSVStudentUpload.objects.get(id=upload_id)
            
            # Check if any students from this upload are registered
            registered_students = csv_upload.students.filter(is_registered=True)
            if registered_students.exists():
                return Response({
                    "error": f"Cannot delete upload. {registered_students.count()} student(s) are already registered."
                }, status=400)
            
            # Delete the upload and all associated students
            deleted_count, _ = csv_upload.students.all().delete()
            csv_upload.delete()
            
            return Response({
                "message": "CSV upload deleted successfully",
                "students_deleted": deleted_count
            })
            
        except CSVStudentUpload.DoesNotExist:
            return Response({"error": "CSV upload not found"}, status=404)


class DownloadCSVTemplateView(APIView):
    permission_classes = [AllowAny]  # Change to AllowAny
    
    def get(self, request):
        """Download CSV template file - Only requires 3 fields"""
        # Create CSV template content
        csv_content = """first_name,last_name,id_number
John,Doe,STU001
Jane,Smith,STU002
Michael,Johnson,STU003

Instructions:
1. First Name: Student's first name (case-insensitive match)
2. Last Name: Student's last name (case-insensitive match)
3. ID Number: Student's ID number (exact match)

Important:
- Do not change the header row
- All 3 fields are required
- ID number must be unique
- First and last names will be matched case-insensitively
- Students will provide email, college, and department during registration
"""
        
        response = HttpResponse(csv_content, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="student_authorization_template.csv"'
        return response

@api_view(['POST'])
@permission_classes([AllowAny])
def check_student_match(request):
    """Check if student name and ID match authorized records"""
    try:
        # Debug: Print the incoming request data
        print(f"Request data received: {request.data}")
        
        # Get and validate fields
        first_name = request.data.get('first_name', '').strip()
        last_name = request.data.get('last_name', '').strip()
        id_number = request.data.get('id_number', '').strip()
        
        print(f"First name: '{first_name}', Last name: '{last_name}', ID: '{id_number}'")
        
        # Check if all fields are present and not empty
        if not first_name:
            return Response({
                "error": "First name is required",
                "details": "Please enter your first name"
            }, status=400)
        
        if not last_name:
            return Response({
                "error": "Last name is required", 
                "details": "Please enter your last name"
            }, status=400)
        
        if not id_number:
            return Response({
                "error": "Student ID is required",
                "details": "Please enter your student ID"
            }, status=400)
        
        # Check database connection and count
        total_students = AuthorizedStudent.objects.count()
        print(f"Total authorized students in database: {total_students}")
        
        # Case-insensitive match for names
        authorized_student = AuthorizedStudent.objects.filter(
            first_name__iexact=first_name,
            last_name__iexact=last_name,
            id_number=id_number,
            is_active=True,
            is_registered=False
        ).first()
        
        if authorized_student:
            print(f"Match found: {authorized_student.first_name} {authorized_student.last_name} - {authorized_student.id_number}")
            return Response({
                "success": True,
                "message": "Information matches authorized records",
                "student": {
                    "first_name": authorized_student.first_name,
                    "last_name": authorized_student.last_name,
                    "id_number": authorized_student.id_number
                }
            })
        else:
            print(f"No match found for: {first_name} {last_name} - {id_number}")
            
            # Check if student exists but is already registered
            already_registered = AuthorizedStudent.objects.filter(
                first_name__iexact=first_name,
                last_name__iexact=last_name,
                id_number=id_number,
                is_registered=True
            ).exists()
            
            if already_registered:
                return Response({
                    "error": "Student already registered",
                    "details": "This student ID is already registered. Please use the login page."
                }, status=400)
            
            # Check if student exists but inactive
            inactive_student = AuthorizedStudent.objects.filter(
                first_name__iexact=first_name,
                last_name__iexact=last_name,
                id_number=id_number,
                is_active=False
            ).exists()
            
            if inactive_student:
                return Response({
                    "error": "Student account inactive",
                    "details": "Your student account is not active. Please contact your department administrator."
                }, status=400)
            
            # No match at all
            return Response({
                "error": "Information doesn't match authorized records",
                "details": "Please check: 1) First name, 2) Last name, and 3) Student ID. They must match exactly with the administrator's records."
            }, status=400)
            
    except Exception as e:
        print(f"Error in check_student_match: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return Response({
            "error": "Internal server error",
            "details": str(e)
        }, status=500)


@api_view(['GET'])
@permission_classes([AllowAny])
def test_authorized_students(request):
    """Test endpoint to check authorized students"""
    students = AuthorizedStudent.objects.all().order_by('id_number')[:5]
    
    student_list = []
    for student in students:
        student_list.append({
            "id": student.id,
            "first_name": student.first_name,
            "last_name": student.last_name,
            "id_number": student.id_number,
            "is_active": student.is_active,
            "is_registered": student.is_registered,
            "email": student.email,
            "college": student.college.name if student.college else None,
            "department": student.department.name if student.department else None
        })
    
    return Response({
        "total_students": AuthorizedStudent.objects.count(),
        "active_students": AuthorizedStudent.objects.filter(is_active=True).count(),
        "registered_students": AuthorizedStudent.objects.filter(is_registered=True).count(),
        "sample_students": student_list
    })



# In views.py:

@api_view(['GET'])
@permission_classes([AllowAny])
def system_status(request):
    """Get current system status"""
    system_control = SystemControl.objects.first()
    
    if not system_control:
        return Response({
            'system_open': True,
            'modules_open': True,
            'message': 'System control not configured'
        })
    
    data = {
        'system_open': system_control.is_open,
        'maintenance': {
            'title': system_control.maintenance_title,
            'message': system_control.maintenance_message,
            'show_page': system_control.show_maintenance_page
        },
        'modules': {
            'departmenthead': system_control.is_department_head_open,
            'librarian': system_control.is_librarian_open,
            'cafeteria': system_control.is_cafeteria_open,
            'dormitory': system_control.is_dormitory_open,
            'registrar': system_control.is_registrar_open,
            'student': system_control.is_student_open,
            'payment': system_control.is_payment_open,
        },
        'scheduled_maintenance': {
            'start': system_control.scheduled_maintenance_start,
            'end': system_control.scheduled_maintenance_end,
            'message': system_control.scheduled_maintenance_message
        }
    }
    
    return Response(data)


@api_view(['GET'])
@permission_classes([AllowAny])
def check_module_access(request):
    """Check if a specific module is accessible"""
    module = request.GET.get('module', '').lower()
    
    if not module:
        return Response({'error': 'Module parameter required'}, status=400)
    
    is_open = SystemControl.get_module_status(module)
    
    return Response({
        'module': module,
        'accessible': is_open,
        'message': f"Module '{module}' is {'open' if is_open else 'closed'}"
    })

# ==================== PAYMENT ENDPOINTS FIXES ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_payments_api(request):
    """Get pending payments for staff verification"""
    # Determine department based on user role
    department_map = {
        'librarian': 'library',
        'cafeteria': 'cafeteria',
        'psychology': 'psychology',
        'sportmaster': 'sportmaster',
        'campuspolice': 'campuspolice',
        'cooperationsharing': 'cooperationsharing',
        'dopcordinator': 'dopcordinator',
        'studentaffairs': 'studentaffairs',
        'dormitory': 'dormitory'
    }
    
    department = department_map.get(request.user.role)
    if not department:
        return Response({"error": "Unauthorized - Not a verification staff"}, status=403)
    
    # Get pending payments for this department
    payments = StudentPayment.objects.filter(
        department_type=department,
        status='pending'
    ).order_by('-created_at')
    
    serializer = StudentPaymentSerializer(payments, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_verified_payments_api(request):
    """Get verified payments for staff"""
    department_map = {
        'librarian': 'library',
        'cafeteria': 'cafeteria',
        'psychology': 'psychology',
        'sportmaster': 'sportmaster',
        'campuspolice': 'campuspolice',
        'cooperationsharing': 'cooperationsharing',
        'dopcordinator': 'dopcordinator',
        'studentaffairs': 'studentaffairs',
        'dormitory': 'dormitory'
    }
    
    department = department_map.get(request.user.role)
    if not department:
        return Response({"error": "Unauthorized - Not a verification staff"}, status=403)
    
    payments = StudentPayment.objects.filter(
        department_type=department,
        status__in=['verified', 'rejected']
    ).order_by('-verified_at')
    
    serializer = StudentPaymentSerializer(payments, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def payment_statistics_api(request):
    """Get payment statistics"""
    user = request.user
    stats = {}
    
    try:
        if user.role == 'student':
            payments = StudentPayment.objects.filter(student=user)
            stats = {
                'total_payments': payments.count(),
                'total_amount': payments.aggregate(Sum('amount'))['amount__sum'] or 0,
                'pending': payments.filter(status='pending').count(),
                'verified': payments.filter(status='verified').count(),
                'rejected': payments.filter(status='rejected').count(),
            }
            
        elif user.role in ['librarian', 'cafeteria', 'dormitory']:
            department_map = {
                'librarian': 'library',
                'cafeteria': 'cafeteria',
                'dormitory': 'dormitory'
            }
            
            department = department_map.get(user.role)
            if not department:
                return Response({"error": "Unauthorized - Not a verification staff"}, status=403)
            
            payments = StudentPayment.objects.filter(department_type=department)
            stats = {
                'total_payments': payments.count(),
                'total_amount': payments.aggregate(Sum('amount'))['amount__sum'] or 0,
                'pending': payments.filter(status='pending').count(),
                'verified': payments.filter(status='verified').count(),
                'rejected': payments.filter(status='rejected').count(),
                'today_pending': payments.filter(
                    status='pending',
                    created_at__date=timezone.now().date()
                ).count(),
                'weekly_pending': payments.filter(
                    status='pending',
                    created_at__gte=timezone.now() - timedelta(days=7)
                ).count(),
            }
            
        elif user.role == 'admin':
            # Calculate department statistics
            library_count = StudentPayment.objects.filter(department_type='library').count()
            cafeteria_count = StudentPayment.objects.filter(department_type='cafeteria').count()
            dormitory_count = StudentPayment.objects.filter(department_type='dormitory').count()
            other_count = StudentPayment.objects.filter(department_type='other').count()
            
            stats = {
                'total_payments': StudentPayment.objects.count(),
                'total_amount': StudentPayment.objects.aggregate(Sum('amount'))['amount__sum'] or 0,
                'pending': StudentPayment.objects.filter(status='pending').count(),
                'verified': StudentPayment.objects.filter(status='verified').count(),
                'rejected': StudentPayment.objects.filter(status='rejected').count(),
                'by_department': {
                    'library': library_count,
                    'cafeteria': cafeteria_count,
                    'dormitory': dormitory_count,
                    'other': other_count,
                }
            }
        
        # Add user info to stats for debugging
        stats['user_role'] = user.role
        stats['user_id'] = user.id
        
        return Response(stats)
        
    except Exception as e:
        print(f"Error in payment_statistics: {str(e)}")
        return Response({"error": f"Error getting statistics: {str(e)}"}, status=500)

# ==================== SIMPLIFIED CHAT ENDPOINTS ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_chat_messages_api(request, room_id):
    """Alias for get_chat_messages_unified for backward compatibility"""
    return get_chat_messages_unified(request, room_id)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_chat_message_api(request):
    """Alias for send_chat_message_unified for backward compatibility"""
    return send_chat_message_unified(request)

# ==================== ADD THESE TO YOUR EXISTING views.py ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_cafeteria_staff(request):
    """Get available cafeteria staff for students to chat with"""
    if request.user.role != 'student':
        return Response({"error": "Only students can access this"}, status=403)
    
    cafeteria_staff = User.objects.filter(role='cafeteria', is_active=True).first()
    
    return Response({
        'role': 'cafeteria',
        'display_name': 'Cafeteria',
        'room_type': 'student_cafeteria',
        'available': cafeteria_staff is not None,
        'staff': {
            'id': cafeteria_staff.id if cafeteria_staff else None,
            'name': cafeteria_staff.get_full_name() if cafeteria_staff else None,
            'email': cafeteria_staff.email if cafeteria_staff else None
        } if cafeteria_staff else None,
        'icon': '🍽️',
        'description': 'Chat about meal dues and cafeteria issues'
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_students_for_cafeteria(request):
    """Get students for cafeteria staff to chat with"""
    if request.user.role != 'cafeteria':
        return Response({"error": "Unauthorized - Cafeteria only"}, status=403)
    
    cafeteria_staff = request.user
    students = User.objects.filter(
        role='student',
        is_active=True
    ).order_by('first_name', 'last_name')[:50]  # Limit for performance
    
    result = []
    for student in students:
        # Check if chat already exists
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=cafeteria_staff,
            room_type='student_cafeteria',
            is_active=True
        ).first()
        
        # Get unread count if chat exists
        unread_count = 0
        if existing_chat:
            unread_count = existing_chat.messages.filter(
                is_read=False
            ).exclude(sender=cafeteria_staff).count()
        
        result.append({
            'id': student.id,
            'full_name': student.get_full_name() or student.username,
            'username': student.username,
            'email': student.email,
            'id_number': getattr(student, 'id_number', 'N/A'),
            'department': student.department.name if student.department else None,
            'has_existing_chat': existing_chat is not None,
            'chat_room_id': existing_chat.id if existing_chat else None,
            'unread_count': unread_count,
            'last_message_time': existing_chat.last_message_time if existing_chat else None
        })
    
    return Response({
        'staff_name': cafeteria_staff.get_full_name() or cafeteria_staff.username,
        'total_students': len(result),
        'students': result
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_cafeteria_chat(request):
    """Start a chat between student and cafeteria - FIXED VERSION"""
    user = request.user
    student_id = request.data.get('student_id')
    
    print(f"Starting cafeteria chat: user_role={user.role}, student_id={student_id}")
    
    # Determine who is starting the chat
    if user.role == 'student':
        # Student starting chat with cafeteria
        student = user
        cafeteria_staff = User.objects.filter(role='cafeteria', is_active=True).first()
        
        if not cafeteria_staff:
            return Response({"error": "No cafeteria staff available"}, status=404)
            
    elif user.role == 'cafeteria':
        # Cafeteria staff starting chat with student
        cafeteria_staff = user
        if not student_id:
            return Response({"error": "Student ID required"}, status=400)
            
        try:
            student = User.objects.get(id=student_id, role='student')
        except User.DoesNotExist:
            return Response({"error": "Student not found"}, status=404)
    else:
        return Response({"error": "Unauthorized"}, status=403)
    
    # Check if chat already exists
    existing_chat = ChatRoom.objects.filter(
        student=student,
        specific_staff=cafeteria_staff,
        room_type='student_cafeteria',
        is_active=True
    ).first()
    
    if existing_chat:
        # Get the last message
        last_msg = existing_chat.messages.last()
        return Response({
            "message": "Chat already exists",
            "chat_room": {
                "id": existing_chat.id,
                "name": existing_chat.name,
                "room_type": existing_chat.room_type,
                "student": {
                    "id": student.id,
                    "name": student.get_full_name() or student.username,
                    "email": student.email,
                    "id_number": getattr(student, 'id_number', 'N/A')
                },
                "staff": {
                    "id": cafeteria_staff.id,
                    "name": cafeteria_staff.get_full_name() or cafeteria_staff.username,
                    "role": cafeteria_staff.role
                },
                "last_message": last_msg.content if last_msg else "",
                "last_message_time": existing_chat.last_message_time,
                "created_at": existing_chat.created_at,
                "unread_count": existing_chat.messages.filter(is_read=False).exclude(sender=user).count()
            }
        })
    
    # Create new chat room
    if user.role == 'student':
        room_name = f"{student.get_full_name() or student.username} - Cafeteria"
    else:
        room_name = f"Cafeteria - {student.get_full_name() or student.username}"
    
    print(f"Creating new chat room: {room_name}")
    
    chat_room = ChatRoom.objects.create(
        name=room_name,
        room_type='student_cafeteria',
        student=student,
        specific_staff=cafeteria_staff,
        is_active=True
    )
    
    # Add participants
    chat_room.participants.add(student, cafeteria_staff)
    
    # Create welcome message
    if user.role == 'student':
        welcome_content = f"Hello, I need assistance with cafeteria clearance."
        sender = student
    else:
        welcome_content = f"Hello {student.get_full_name() or student.username}! This is {cafeteria_staff.get_full_name() or cafeteria_staff.username} from Cafeteria. How can I help you with your meal dues?"
        sender = cafeteria_staff
    
    welcome_msg = Message.objects.create(
        room=chat_room,
        sender=sender,
        message_type='text',
        content=welcome_content
    )
    
    chat_room.last_message_time = welcome_msg.created_at
    chat_room.save()
    
    # Create notification for the other participant
    other_participant = cafeteria_staff if user.role == 'student' else student
    Notification.objects.create(
        user=other_participant,
        title="New Chat Started",
        message=f"{sender.get_full_name() or sender.username} started a chat with you.",
        notification_type='chat'
    )
    
    return Response({
        "message": "Chat started successfully",
        "chat_room": {
            "id": chat_room.id,
            "name": chat_room.name,
            "room_type": chat_room.room_type,
            "student": {
                "id": student.id,
                "name": student.get_full_name() or student.username,
                "email": student.email,
                "id_number": getattr(student, 'id_number', 'N/A')
            },
            "staff": {
                "id": cafeteria_staff.id,
                "name": cafeteria_staff.get_full_name() or cafeteria_staff.username,
                "role": cafeteria_staff.role
            },
            "last_message": welcome_msg.content,
            "last_message_time": chat_room.last_message_time,
            "created_at": chat_room.created_at,
            "unread_count": 0
        }
    }, status=201)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_cafeteria_chat_messages(request, room_id):
    """Get messages for a specific cafeteria chat room - FIXED VERSION"""
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Mark unread messages as read (excluding user's own messages)
        Message.objects.filter(
            room=chat_room,
            is_read=False
        ).exclude(sender=user).update(is_read=True)
        
        # Get messages
        messages = chat_room.messages.all().order_by('created_at')
        
        # Format messages
        formatted_messages = []
        for message in messages:
            msg_data = {
                "id": message.id,
                "content": message.content,
                "message_type": message.message_type,
                "sender": {
                    "id": message.sender.id if message.sender else None,
                    "username": message.sender.username if message.sender else None,
                    "full_name": message.sender.get_full_name() if message.sender else None,
                    "role": message.sender.role if message.sender else None
                },
                "is_read": message.is_read,
                "created_at": message.created_at,
                "is_own": message.sender == user
            }
            
            # Add file URLs if present
            if message.image_file:
                msg_data["image_file"] = message.image_file.url
            if message.audio_file:
                msg_data["audio_file"] = message.audio_file.url
            if message.video_file:
                msg_data["video_file"] = message.video_file.url
            if message.file:
                msg_data["file"] = message.file.url
                msg_data["file_name"] = message.file_name
                msg_data["file_size"] = message.file_size
            if message.thumbnail:
                msg_data["thumbnail"] = message.thumbnail.url
            
            formatted_messages.append(msg_data)
        
        # Get room info
        room_info = {
            "id": chat_room.id,
            "name": chat_room.name,
            "room_type": chat_room.room_type,
            "student": {
                "id": chat_room.student.id if chat_room.student else None,
                "name": chat_room.student.get_full_name() if chat_room.student else None,
                "email": chat_room.student.email if chat_room.student else None,
                "id_number": getattr(chat_room.student, 'id_number', 'N/A') if chat_room.student else 'N/A'
            } if chat_room.student else None,
            "staff": {
                "id": chat_room.specific_staff.id if chat_room.specific_staff else None,
                "name": chat_room.specific_staff.get_full_name() if chat_room.specific_staff else None,
                "role": chat_room.specific_staff.role if chat_room.specific_staff else None
            } if chat_room.specific_staff else None
        }
        
        return Response({
            'room': room_info,
            'messages': formatted_messages,
            'total_messages': messages.count()
        })
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        print(f"Error getting chat messages: {e}")
        return Response({"error": str(e)}, status=500)
@api_view(['POST'])


@permission_classes([IsAuthenticated])
def send_cafeteria_message(request):
    """Send a message in cafeteria chat - FIXED VERSION"""
    room_id = request.data.get('room_id')
    content = request.data.get('content')
    
    if not room_id:
        return Response({"error": "room_id required"}, status=400)
    
    if not content:
        return Response({"error": "Message content required"}, status=400)
    
    try:
        chat_room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in chat_room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Create message
        message = Message.objects.create(
            room=chat_room,
            sender=user,
            content=content,
            message_type='text'
        )
        
        # Update room's last message time
        chat_room.last_message_time = message.created_at
        chat_room.save(update_fields=['last_message_time'])
        
        # Create notification for other participants
        other_participants = chat_room.participants.exclude(id=user.id)
        
        for participant in other_participants:
            Notification.objects.create(
                user=participant,
                title=f"New message from {user.get_full_name() or user.username}",
                message=content[:100],
                notification_type='chat'
            )
        
        # Prepare response
        response_data = {
            "id": message.id,
            "content": message.content,
            "message_type": message.message_type,
            "sender": {
                "id": user.id,
                "username": user.username,
                "full_name": user.get_full_name() or user.username,
                "role": user.role
            },
            "is_read": message.is_read,
            "created_at": message.created_at,
            "is_own": True
        }
        
        return Response(response_data, status=201)
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        print(f"Error sending message: {e}")
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_cafeteria_chat_rooms(request):
    """Get chat rooms for cafeteria staff - FIXED VERSION"""
    if request.user.role != 'cafeteria':
        return Response({"error": "Unauthorized - Cafeteria only"}, status=403)
    
    user = request.user
    
    # Get chat rooms where user is a participant
    rooms = ChatRoom.objects.filter(
        participants=user,
        room_type='student_cafeteria',
        is_active=True
    ).distinct().order_by('-last_message_time')
    
    result = []
    for room in rooms:
        last_msg = room.messages.last()
        unread_count = room.messages.filter(is_read=False).exclude(sender=user).count()
        
        # Get student info
        student = room.student
        if not student:
            # Try to find student from participants
            student = room.participants.filter(role='student').first()
        
        result.append({
            "id": room.id,
            "name": room.name,
            "room_type": room.room_type,
            "last_message": last_msg.content[:100] if last_msg else "",
            "last_message_time": room.last_message_time,
            "unread_count": unread_count,
            "student": {
                "id": student.id if student else None,
                "name": student.get_full_name() if student else "Unknown Student",
                "username": student.username if student else "unknown",
                "email": student.email if student else "",
                "id_number": getattr(student, 'id_number', 'N/A') if student else 'N/A'
            } if student else None,
            "created_at": room.created_at
        })
    
    return Response(result)
# ==================== DORMITORY CHAT ENDPOINTS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_dormitory_chat_rooms(request):
    """Get chat rooms for dormitory staff"""
    if request.user.role != 'dormitory':
        return Response({"error": "Unauthorized - Dormitory only"}, status=403)
    
    user = request.user
    rooms = ChatRoom.objects.filter(
        Q(specific_staff=user) | Q(participants=user),
        room_type='student_dormitory',
        is_active=True
    ).distinct().order_by('-last_message_time')
    
    result = []
    for room in rooms:
        last_msg = room.messages.last()
        unread_count = room.messages.filter(is_read=False).exclude(sender=user).count()
        
        # Get student info
        student = room.student
        if not student:
            # Try to find student from participants
            student = room.participants.filter(role='student').first()
        
        result.append({
            "id": room.id,
            "name": room.name,
            "last_message": last_msg.content[:100] if last_msg else "",
            "last_message_time": room.last_message_time,
            "unread_count": unread_count,
            "student": {
                "id": student.id if student else None,
                "name": student.get_full_name() if student else "Unknown Student",
                "username": student.username if student else "unknown",
                "email": student.email if student else "",
                "id_number": getattr(student, 'id_number', 'N/A') if student else 'N/A'
            } if student else None,
            "created_at": room.created_at
        })
    
    return Response(result)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_dormitory_chat_messages(request, room_id):
    """Get messages for a dormitory chat room"""
    try:
        room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Mark messages as read
        room.messages.filter(is_read=False).exclude(sender=user).update(is_read=True)
        
        messages = room.messages.all().order_by('created_at')
        
        result = []
        for msg in messages:
            msg_data = {
                "id": msg.id,
                "content": msg.content,
                "message_type": msg.message_type,
                "sender": {
                    "id": msg.sender.id,
                    "username": msg.sender.username,
                    "full_name": msg.sender.get_full_name(),
                    "role": msg.sender.role
                },
                "is_read": msg.is_read,
                "created_at": msg.created_at,
                "is_own": msg.sender == user
            }
            
            # Add file URLs if present
            if msg.image_file:
                msg_data["image_file"] = msg.image_file.url
            if msg.audio_file:
                msg_data["audio_file"] = msg.audio_file.url
            if msg.video_file:
                msg_data["video_file"] = msg.video_file.url
            if msg.file:
                msg_data["file"] = msg.file.url
                msg_data["file_name"] = msg.file_name
                msg_data["file_size"] = msg.file_size
            if msg.thumbnail:
                msg_data["thumbnail"] = msg.thumbnail.url
            
            result.append(msg_data)
        
        return Response({
            "room_id": room.id,
            "room_name": room.name,
            "messages": result,
            "total_messages": len(result)
        })
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_dormitory_chat(request):
    """Start a new chat between dormitory staff and student"""
    if request.user.role != 'dormitory':
        return Response({"error": "Unauthorized - Dormitory only"}, status=403)
    
    student_id = request.data.get('student_id')
    
    if not student_id:
        return Response({"error": "Student ID is required"}, status=400)
    
    try:
        # Get the student
        student = User.objects.get(id=student_id, role='student', is_active=True)
        dormitory_staff = request.user
        
        # Check if chat already exists
        existing_chat = ChatRoom.objects.filter(
            Q(student=student) | Q(participants=student),
            Q(specific_staff=dormitory_staff) | Q(participants=dormitory_staff),
            room_type='student_dormitory',
            is_active=True
        ).first()
        
        if existing_chat:
            return Response({
                "message": "Chat already exists",
                "chat_room": {
                    "id": existing_chat.id,
                    "name": existing_chat.name,
                    "room_type": existing_chat.room_type
                },
                "existing": True
            })
        
        # Create new chat room
        room_name = f"{student.get_full_name() or student.username} - Dormitory"
        
        chat_room = ChatRoom.objects.create(
            name=room_name,
            room_type='student_dormitory',
            student=student,
            specific_staff=dormitory_staff,
            is_active=True
        )
        
        # Add participants
        chat_room.participants.add(student, dormitory_staff)
        
        # Create welcome message
        welcome_content = f"Hello {student.get_full_name() or student.username}! This is {dormitory_staff.get_full_name() or dormitory_staff.username} from Dormitory. How can I help you with your clearance?"
        
        welcome_msg = Message.objects.create(
            room=chat_room,
            sender=dormitory_staff,
            message_type='text',
            content=welcome_content
        )
        
        chat_room.last_message_time = welcome_msg.created_at
        chat_room.save()
        
        # Create notification for student
        Notification.objects.create(
            user=student,
            title="New Chat from Dormitory",
            message=f"{dormitory_staff.get_full_name() or dormitory_staff.username} from Dormitory started a chat with you.",
            notification_type='chat'
        )
        
        return Response({
            "message": "Chat started successfully",
            "chat_room": {
                "id": chat_room.id,
                "name": chat_room.name,
                "room_type": chat_room.room_type,
                "student": {
                    "id": student.id,
                    "name": student.get_full_name() or student.username,
                    "email": student.email,
                    "id_number": getattr(student, 'id_number', 'N/A')
                },
                "staff": {
                    "id": dormitory_staff.id,
                    "name": dormitory_staff.get_full_name() or dormitory_staff.username,
                    "role": dormitory_staff.role
                },
                "last_message": welcome_msg.content,
                "last_message_time": chat_room.last_message_time,
                "created_at": chat_room.created_at
            }
        }, status=201)
        
    except User.DoesNotExist:
        return Response({"error": "Student not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_dormitory_message(request):
    """Send a message in dormitory chat"""
    room_id = request.data.get('room_id')
    content = request.data.get('content')
    
    if not room_id:
        return Response({"error": "room_id is required"}, status=400)
    
    if not content:
        return Response({"error": "Message content is required"}, status=400)
    
    try:
        room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        # Create message
        message = Message.objects.create(
            room=room,
            sender=user,
            content=content,
            message_type='text'
        )
        
        # Update room's last message time
        room.last_message_time = message.created_at
        room.save(update_fields=['last_message_time'])
        
        # Create notification for the other participant
        other_participant = room.student if user.role == 'dormitory' else room.specific_staff
        
        if other_participant:
            Notification.objects.create(
                user=other_participant,
                title=f"New message from {user.get_full_name() or user.username}",
                message=content[:100],
                notification_type='chat'
            )
        
        # Prepare response
        response_data = {
            "id": message.id,
            "content": message.content,
            "message_type": message.message_type,
            "sender": {
                "id": user.id,
                "username": user.username,
                "full_name": user.get_full_name(),
                "role": user.role
            },
            "is_read": message.is_read,
            "created_at": message.created_at,
            "is_own": True
        }
        
        return Response(response_data, status=201)
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def upload_dormitory_file(request):
    """Upload a file in dormitory chat"""
    room_id = request.data.get('room_id')
    message_type = request.data.get('message_type', 'file')
    
    if not room_id:
        return Response({"error": "room_id is required"}, status=400)
    
    try:
        room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        # Check if user is a participant
        if user not in room.participants.all():
            return Response({"error": "You are not a participant in this chat"}, status=403)
        
        message_data = {
            'room': room,
            'sender': user,
            'message_type': message_type
        }
        
        # Handle different file types
        if message_type == 'image':
            if 'image_file' in request.FILES:
                image_file = request.FILES['image_file']
                message_data['image_file'] = image_file
                message_data['file_name'] = image_file.name
                message_data['file_size'] = image_file.size
                
                # Generate thumbnail
                try:
                    from PIL import Image
                    from io import BytesIO
                    from django.core.files.base import ContentFile
                    
                    img = Image.open(image_file)
                    img.thumbnail((200, 200))
                    thumb_io = BytesIO()
                    img.save(thumb_io, format='JPEG', quality=85)
                    
                    message_data['thumbnail'] = ContentFile(
                        thumb_io.getvalue(),
                        name=f"thumb_{image_file.name}"
                    )
                except Exception as e:
                    print(f"Thumbnail generation failed: {e}")
                    
        elif message_type == 'audio':
            if 'audio_file' in request.FILES:
                audio_file = request.FILES['audio_file']
                message_data['audio_file'] = audio_file
                message_data['file_name'] = audio_file.name
                message_data['file_size'] = audio_file.size
                
        elif message_type == 'video':
            if 'video_file' in request.FILES:
                video_file = request.FILES['video_file']
                message_data['video_file'] = video_file
                message_data['file_name'] = video_file.name
                message_data['file_size'] = video_file.size
                
        else:  # file
            if 'file' in request.FILES:
                file_obj = request.FILES['file']
                message_data['file'] = file_obj
                message_data['file_name'] = file_obj.name
                message_data['file_size'] = file_obj.size
        
        # Create message
        message = Message.objects.create(**message_data)
        
        # Update room's last message time
        room.last_message_time = message.created_at
        room.save(update_fields=['last_message_time'])
        
        # Create notification for other participant
        other_participant = room.student if user.role == 'dormitory' else room.specific_staff
        
        if other_participant:
            Notification.objects.create(
                user=other_participant,
                title=f"New {message_type} from {user.get_full_name() or user.username}",
                message=f"Sent a {message_type}",
                notification_type='chat'
            )
        
        # Prepare response
        response_data = {
            "id": message.id,
            "message_type": message.message_type,
            "sender": {
                "id": user.id,
                "username": user.username,
                "full_name": user.get_full_name(),
                "role": user.role
            },
            "is_read": message.is_read,
            "created_at": message.created_at,
            "is_own": True
        }
        
        if message.image_file:
            response_data["image_file"] = message.image_file.url
        if message.audio_file:
            response_data["audio_file"] = message.audio_file.url
        if message.video_file:
            response_data["video_file"] = message.video_file.url
        if message.file:
            response_data["file"] = message.file.url
        if message.file_name:
            response_data["file_name"] = message.file_name
        if message.file_size:
            response_data["file_size"] = message.file_size
        if message.thumbnail:
            response_data["thumbnail"] = message.thumbnail.url
        
        return Response(response_data, status=201)
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_dormitory_students_for_chat(request):
    """Get list of students for dormitory staff to chat with"""
    if request.user.role != 'dormitory':
        return Response({"error": "Unauthorized - Dormitory only"}, status=403)
    
    dormitory_staff = request.user
    
    # Get all active students
    students = User.objects.filter(
        role='student',
        is_active=True
    ).order_by('first_name', 'last_name')[:100]  # Limit for performance
    
    result = []
    for student in students:
        # Check if chat already exists
        existing_chat = ChatRoom.objects.filter(
            student=student,
            specific_staff=dormitory_staff,
            room_type='student_dormitory',
            is_active=True
        ).first()
        
        # Get unread count if chat exists
        unread_count = 0
        if existing_chat:
            unread_count = existing_chat.messages.filter(
                is_read=False
            ).exclude(sender=dormitory_staff).count()
        
        result.append({
            'id': student.id,
            'full_name': student.get_full_name() or student.username,
            'username': student.username,
            'email': student.email,
            'id_number': getattr(student, 'id_number', 'N/A'),
            'department': student.department.name if student.department else None,
            'has_existing_chat': existing_chat is not None,
            'chat_room_id': existing_chat.id if existing_chat else None,
            'unread_count': unread_count,
            'last_message_time': existing_chat.last_message_time if existing_chat else None
        })
    
    return Response({
        'staff_name': dormitory_staff.get_full_name() or dormitory_staff.username,
        'total_students': len(result),
        'students': result
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_dormitory_messages_read(request, room_id):
    """Mark all messages in a room as read"""
    try:
        room = ChatRoom.objects.get(id=room_id, is_active=True)
        user = request.user
        
        if user not in room.participants.all():
            return Response({"error": "Not a participant"}, status=403)
        
        updated_count = room.messages.filter(
            is_read=False
        ).exclude(sender=user).update(is_read=True)
        
        return Response({
            "message": f"Marked {updated_count} messages as read",
            "count": updated_count
        })
        
    except ChatRoom.DoesNotExist:
        return Response({"error": "Chat room not found"}, status=404)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_dormitory_message(request, message_id):
    """Delete a message"""
    try:
        message = Message.objects.get(id=message_id)
        
        if message.sender != request.user:
            return Response({"error": "You can only delete your own messages"}, status=403)
        
        # Delete associated files
        if message.image_file:
            message.image_file.delete(save=False)
        if message.audio_file:
            message.audio_file.delete(save=False)
        if message.video_file:
            message.video_file.delete(save=False)
        if message.file:
            message.file.delete(save=False)
        if message.thumbnail:
            message.thumbnail.delete(save=False)
        
        message.delete()
        
        return Response({"message": "Message deleted successfully"})
        
    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=404)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_dormitory_file(request, message_id):
    """Download a file from a message"""
    try:
        message = Message.objects.get(id=message_id)
        user = request.user
        
        if user not in message.room.participants.all():
            return Response({"error": "Unauthorized"}, status=403)
        
        # Determine which file to download
        file_field = None
        if message.file:
            file_field = message.file
        elif message.image_file:
            file_field = message.image_file
        elif message.audio_file:
            file_field = message.audio_file
        elif message.video_file:
            file_field = message.video_file
        
        if not file_field:
            return Response({"error": "No file found"}, status=404)
        
        file_path = file_field.path
        if not os.path.exists(file_path):
            return Response({"error": "File not found"}, status=404)
        
        response = FileResponse(
            open(file_path, 'rb'),
            content_type='application/octet-stream'
        )
        filename = message.file_name or os.path.basename(file_path)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
        
    except Message.DoesNotExist:
        return Response({"error": "Message not found"}, status=404)