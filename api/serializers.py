from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import serializers
from .models import PaymentMethod, StudentPayment, PaymentVerificationLog
import os
from django.core.exceptions import ValidationError
import re
from .models import (
    User, ClearanceForm, Department, College,
    SystemControl, PasswordResetOTP, Notification,
    SystemControlRequest, FormAccessRequest,
    ClearanceFormStatusHistory, ChatRoom, Message,AuthorizedStudent,CSVStudentUpload,Building  
)

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    department = serializers.SerializerMethodField()
    password = serializers.CharField(write_only=True, required=False)
    building_info = serializers.SerializerMethodField()
    assigned_buildings_info = serializers.SerializerMethodField()
    assigned_buildings_details = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'password', 'role', 
            'department', 'is_blocked', 'building', 'building_info',
            'assigned_buildings', 'assigned_buildings_info', 'assigned_buildings_details',
            'first_name', 'last_name', 'phone'
        ]
        read_only_fields = ['created_at']

    def get_department(self, obj):
        """Get department information"""
        if obj.department:
            return {
                "id": obj.department.id,
                "name": obj.department.name
            }
        return None


    def get_building_info(self, obj):
        """Get student's residential building info"""
        if obj.building:
            return {
                "id": obj.building.id,
                "name": obj.building.name,
                "code": obj.building.code
            }
        return None
    
    def get_assigned_buildings_info(self, obj):
        """Get buildings assigned to dormitory staff"""
        if obj.role == 'dormitory':
            buildings = obj.assigned_buildings.all()
            return [
                {
                    "id": b.id,
                    "name": b.name,
                    "code": b.code,
                    "capacity": b.capacity,
                    "student_count": b.building_students.filter(is_active=True).count()
                }
                for b in buildings
            ]
        return []

    def get_assigned_buildings_details(self, obj):
        """Get detailed building info with student counts"""
        if obj.role == 'dormitory':
            buildings = obj.assigned_buildings.all()
            details = []
            for building in buildings:
                students = User.objects.filter(
                    role='student',
                    building=building,
                    is_active=True
                )
                details.append({
                    "id": building.id,
                    "name": building.name,
                    "code": building.code,
                    "capacity": building.capacity,
                    "student_count": students.count(),
                    "students": [
                        {
                            "id": s.id,
                            "username": s.username,
                            "full_name": s.get_full_name(),
                            "email": s.email,
                            "id_number": s.id_number
                        }
                        for s in students[:10]  # Limit to 10 students for performance
                    ],
                    "pending_forms": ClearanceForm.objects.filter(
                        student__in=students,
                        status="approved_studentaffairs"
                    ).count()
                })
            return details
        return []


    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user



# In your serializers.py - Add this new serializer

class DormitoryStaffAssignmentSerializer(serializers.Serializer):
    """Serializer for assigning buildings to dormitory staff"""
    staff_id = serializers.IntegerField(required=True)
    building_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=True,
        allow_empty=True
    )
    
    def validate_staff_id(self, value):
        try:
            staff = User.objects.get(id=value, role='dormitory')
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError("Dormitory staff not found")
    
    def validate_building_ids(self, value):
        if not value:
            return value  # Allow empty list (unassign all)
        
        # Validate all buildings exist and are active
        buildings = Building.objects.filter(id__in=value, is_active=True)
        if buildings.count() != len(value):
            found_ids = set(buildings.values_list('id', flat=True))
            missing_ids = set(value) - found_ids
            raise serializers.ValidationError(
                f"Buildings not found or inactive: {list(missing_ids)}"
            )
        return value
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    id_number = serializers.CharField(required=True)
    college = serializers.PrimaryKeyRelatedField(
        queryset=College.objects.all(),
        required=True
    )
    department = serializers.PrimaryKeyRelatedField(
        queryset=Department.objects.all(),
        required=True
    )
     # Add building field - IMPORTANT: Building must be imported at the top
    building = serializers.PrimaryKeyRelatedField(
        queryset=Building.objects.filter(is_active=True),  # Only show active buildings
        required=True,
        help_text="Select your dormitory building"
    )
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'password', 'confirm_password',
            'first_name', 'last_name', 'role', 'id_number',
            'college', 'department','building'
        ]
        extra_kwargs = {
            'username': {'required': False},  # We'll generate it automatically
            'role': {'default': 'student', 'read_only': True}
        }
    
    def validate(self, data):
        # Check if passwords match
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        
        # Check if email already exists
        email = data.get('email')
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "This email is already registered."})
        
        # Check if id_number already exists
        id_number = data.get('id_number')
        if User.objects.filter(id_number=id_number).exists():
            raise serializers.ValidationError({"id_number": "This ID number is already registered."})
        
        
         # Validate building is active
        building = data.get('building')
        if building and not building.is_active:
            raise serializers.ValidationError({"building": "Selected building is not active."})
        # Generate username if not provided
        if not data.get('username'):
            first_name = data.get('first_name', '').lower().replace(' ', '_')
            last_name = data.get('last_name', '').lower().replace(' ', '_')
            id_number = data.get('id_number', '')
            if first_name and last_name and id_number:
                username = f"{first_name}_{last_name}_{id_number}"
                # Check if username already exists
                if User.objects.filter(username=username).exists():
                    # Add timestamp to make it unique
                    timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
                    username = f"{first_name}_{last_name}_{id_number}_{timestamp}"
                data['username'] = username
            else:
                raise serializers.ValidationError({"username": "Could not generate username. Please provide first name, last name, and ID number."})
        
        return data
    
    def create(self, validated_data):
        # Remove confirm_password from validated_data
        validated_data.pop('confirm_password', None)
        
        # Ensure role is student
        validated_data['role'] = 'student'
        
        # Create user
        user = User.objects.create_user(**validated_data)
        return user

class AdminCreateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ["username", "password", "role", "email", "department"]

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        return super().create(validated_data)

# Profile Management Serializers
class ChangeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'phone'
        ]
        extra_kwargs = {
            'username': {'required': False},
            'email': {'required': False},
        }
    
    def validate_username(self, value):
        if User.objects.filter(username=value).exclude(pk=self.instance.pk).exists():
            raise serializers.ValidationError("Username already exists.")
        return value
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exclude(pk=self.instance.pk).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True, min_length=8)
    confirm_password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data
    
    def validate_new_password(self, value):
        # Password strength validation
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value

# buildig create

class BuildingSerializer(serializers.ModelSerializer):
    student_count = serializers.SerializerMethodField()
    staff_count = serializers.SerializerMethodField()
    form_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Building
        fields = [
            'id', 'name', 'code', 'address', 'capacity',
            'is_active', 'student_count', 'staff_count', 'form_count',
            'created_at'
        ]
        read_only_fields = ['created_at']
    
    def get_student_count(self, obj):
        return obj.building_students.filter(is_active=True).count()
    
    def get_staff_count(self, obj):
        return obj.assigned_staff.count()
    
    def get_form_count(self, obj):
        return obj.form_buildings.filter(status='approved_studentaffairs').count()
class ProfilePictureSerializer(serializers.ModelSerializer):
    profile_picture_url = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['profile_picture', 'profile_picture_url']
        read_only_fields = ['profile_picture_url']
    
    def get_profile_picture_url(self, obj):
        return obj.get_profile_picture_url()
    
    

class UserProfileSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.name', read_only=True)
    college_name = serializers.CharField(source='department.college.name', read_only=True)
    profile_picture_url = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'department', 'department_name', 'college_name',
            'phone', 'is_blocked', 'is_active',
            'date_joined', 'last_login', 'last_password_change',
            'profile_picture', 'profile_picture_url'
        ]
        read_only_fields = [
            'id', 'date_joined', 'last_login', 'last_password_change',
            'is_blocked', 'is_active'
        ]
    
    def get_profile_picture_url(self, obj):
        return obj.get_profile_picture_url()


# Clearance Form Serializers
class ClearanceFormStatusHistorySerializer(serializers.ModelSerializer):
    changed_by = UserSerializer(read_only=True)

    class Meta:
        model = ClearanceFormStatusHistory
        fields = "__all__"

class ClearanceFormSerializer(serializers.ModelSerializer):
    student = UserSerializer(read_only=True)
    status_history = ClearanceFormStatusHistorySerializer(many=True, read_only=True)
    student_building_info = serializers.SerializerMethodField()
    class Meta:
        model = ClearanceForm
        fields = "__all__"
        read_only_fields = [
            "status", "created_at",
            "updated_at", "cleared_at"
        ]
        
    def get_student_building_info(self, obj):
        """Get student building information"""
        if obj.student_building:
            return {
                "id": obj.student_building.id,
                "name": obj.student_building.name,
                "code": obj.student_building.code
            }
        return None

    def create(self, validated_data):
        # keep department_name as provided
        return super().create(validated_data)

# College and Department Serializers
class CollegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = College
        fields = ["id", "name", "created_at"]
        read_only_fields = ["id", "created_at"]

class DepartmentSerializer(serializers.ModelSerializer):
    college = serializers.PrimaryKeyRelatedField(
        queryset=College.objects.all(),
        allow_null=True,
        required=False
    )

    college_name = serializers.CharField(
        source="college.name",
        read_only=True
    )

    class Meta:
        model = Department
        fields = ["id", "name", "college", "college_name", "created_at"]

# System Control Serializers
class SystemControlSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemControl
        fields = '__all__'
    
    def create(self, validated_data):
        # Ensure all boolean fields have defaults
        defaults = {
            'is_department_head_open': True,
            'is_librarian_open': True,
            'is_cafeteria_open': True,
            'is_dormitory_open': True,
            'is_registrar_open': True,
            'is_student_open': True,
            'is_payment_open': True,
            'show_maintenance_page': True,
        }
        
        # Merge defaults with validated data
        for key, value in defaults.items():
            if key not in validated_data:
                validated_data[key] = value
        
        return super().create(validated_data)

class SystemAccessRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemControlRequest
        fields = ["id", "email", "status", "reason", "created_at"]
        read_only_fields = ["status", "reason", "created_at"]

class FormAccessRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = FormAccessRequest
        fields = '__all__'

# Password Reset Serializers
class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=6)

# Notification Serializer
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = "__all__"


class MessageSerializer(serializers.ModelSerializer):
    """Serializer for Message model - FIXED VERSION"""
    sender = UserSerializer(read_only=True)
    sender_name = serializers.SerializerMethodField()
    room = serializers.PrimaryKeyRelatedField(read_only=True)
    file_url = serializers.SerializerMethodField()
    thumbnail_url = serializers.SerializerMethodField()
    is_own = serializers.SerializerMethodField()
    
    class Meta:
        model = Message
        fields = [
            'id', 'room', 'sender', 'sender_name', 'content', 'message_type',
            'file', 'audio_file', 'video_file', 'image_file',
            'file_url', 'thumbnail_url', 'file_name', 'file_size', 'duration',
            'is_read', 'created_at', 'updated_at', 'is_own'
        ]
        read_only_fields = ['created_at', 'updated_at', 'is_read']

    def get_sender_name(self, obj):
        return obj.sender.get_full_name() or obj.sender.username

    def get_file_url(self, obj):
        return obj.get_file_url() if hasattr(obj, 'get_file_url') else None

    def get_thumbnail_url(self, obj):
        if hasattr(obj, 'thumbnail') and obj.thumbnail:
            return obj.thumbnail.url
        return None

    def get_is_own(self, obj):
        request = self.context.get('request')
        if request and request.user:
            return obj.sender == request.user
        return False


# api/serializers.py

class ChatRoomSerializer(serializers.ModelSerializer):
    """Serializer for ChatRoom model - FIXED VERSION"""
    participants = UserSerializer(many=True, read_only=True)
    participants_count = serializers.SerializerMethodField()
    student = UserSerializer(read_only=True)
    specific_staff = UserSerializer(read_only=True)
    department = DepartmentSerializer(read_only=True)
    
    # FIX: Use string for last_message to match React expectation
    last_message = serializers.SerializerMethodField()
    last_message_time = serializers.DateTimeField(read_only=True)
    unread_count = serializers.SerializerMethodField()
    other_participant = serializers.SerializerMethodField()
    
    class Meta:
        model = ChatRoom
        fields = [
            'id', 'name', 'room_type', 'student', 'department',
            'specific_staff', 'participants', 'participants_count',
            'is_active', 'last_message', 'last_message_time',
            'unread_count', 'other_participant',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_participants_count(self, obj):
        return obj.participants.count()

    def get_last_message(self, obj):
        """Return just the content as string - NOT an object"""
        last_msg = obj.messages.last()
        if last_msg:
            # Return ONLY the string content, not an object
            return last_msg.content[:100] if last_msg.content else f"[{last_msg.message_type}]"
        return ""

    def get_unread_count(self, obj):
        request = self.context.get('request')
        if request and request.user:
            return obj.messages.filter(
                is_read=False
            ).exclude(sender=request.user).count()
        return 0

    def get_other_participant(self, obj):
        request = self.context.get('request')
        if request and request.user:
            other = obj.participants.exclude(id=request.user.id).first()
            if other:
                return {
                    'id': other.id,
                    'username': other.username,
                    'full_name': other.get_full_name(),
                    'role': other.role,
                    'department': other.department.name if other.department else None,
                }
        return None
class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = [
            'id', 'name', 'account_name', 'account_number', 
            'phone_number', 'instructions', 'is_active', 
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def validate(self, data):
        # Get the name
        name = data.get('name')
        if not name and self.instance:
            name = self.instance.name
        
        # Get account number
        account_number = data.get('account_number')
        if account_number is None and self.instance:
            account_number = self.instance.account_number
        
        # Skip if no account number
        if account_number is None or not account_number:
            return data
        
        account_str = str(account_number).strip()
        name_lower = name.lower() if name else ''
        
        # Check for CBE (Commercial Bank of Ethiopia) variations
        cbe_patterns = ['cbe', 'commercial bank', 'commercial bank of ethiopia']
        is_cbe = any(pattern in name_lower for pattern in cbe_patterns)
        
        # Check for Nib International Bank variations
        nib_patterns = ['nib', 'nib international', 'nib bank', 'nib international bank']
        is_nib = any(pattern in name_lower for pattern in nib_patterns)
        
        # Validate digits only
        if not account_str.isdigit():
            raise serializers.ValidationError({
                "account_number": "Account number must contain only digits."
            })
        
        # CBE validation - exactly 13 digits
        if is_cbe:
            if len(account_str) != 13:
                raise serializers.ValidationError({
                    "account_number": f"CBE account number must be exactly 13 digits. You provided {len(account_str)} digits."
                })
        
        # Nib International Bank validation - exactly 13 digits
        elif is_nib:
            if len(account_str) != 13:
                raise serializers.ValidationError({
                    "account_number": f"Nib International Bank account number must be exactly 13 digits. You provided {len(account_str)} digits."
                })
        
        # Other banks - 5-13 digits
        else:
            if len(account_str) < 5 or len(account_str) > 13:
                raise serializers.ValidationError({
                    "account_number": f"Account number must be between 5 and 13 digits. You provided {len(account_str)} digits."
                })
        
        return data

class StudentPaymentSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.get_full_name', read_only=True)
    student_id = serializers.CharField(source='student.id_number', read_only=True)
    payment_method_name = serializers.CharField(source='payment_method.get_name_display', read_only=True)
    verified_by_name = serializers.CharField(source='verified_by.get_full_name', read_only=True)
    clearance_form_id = serializers.IntegerField(source='clearance_form.id', read_only=True)
    receipt_url = serializers.SerializerMethodField()
    receipt_filename = serializers.SerializerMethodField()
    
    class Meta:
        model = StudentPayment
        fields = [
            'id', 'student', 'student_name', 'student_id',
            'clearance_form', 'clearance_form_id',
            'payment_method', 'payment_method_name',
            'department_type', 'transaction_id', 'amount',
            'receipt_file', 'receipt_url', 'receipt_filename',
            'status', 'verified_by', 'verified_by_name',
            'verified_at', 'rejection_reason',
            'phone_number', 'account_last_digits',
            'payment_date', 'created_at', 'updated_at','note'
        ]
        read_only_fields = ['status', 'verified_by', 'verified_at','rejection_reason']
    
    def get_receipt_url(self, obj):
        if obj.receipt_file:
            return obj.receipt_file.url
        return None
    
    def get_receipt_filename(self, obj):
        if obj.receipt_file:
            return os.path.basename(obj.receipt_file.name)
        return None
    
    def validate(self, data):
        # Ensure student is making the payment
        request = self.context.get('request')
        if request and request.user.role != 'student':
            raise serializers.ValidationError("Only students can submit payments")
        
        # Check if payment method is active
        if data.get('payment_method') and not data['payment_method'].is_active:
            raise serializers.ValidationError("This payment method is not active")
        
        # Validate amount is positive
        if data.get('amount', 0) <= 0:
            raise serializers.ValidationError("Amount must be greater than 0")
        
        return data

class PaymentSubmissionSerializer(serializers.ModelSerializer):
    """Serializer for submitting payment"""
    clearance_form_id = serializers.IntegerField(required=False, allow_null=True)
    payment_method_id = serializers.IntegerField(required=True)
    department_type = serializers.ChoiceField(
        choices=['library', 'cafeteria', 'dormitory', 'other'],
        required=True
    )
    transaction_id = serializers.CharField(max_length=100, required=True)
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, required=True)
    phone_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    account_last_digits = serializers.CharField(max_length=4, required=False, allow_blank=True)
    payment_date = serializers.DateField(required=True)
    note = serializers.CharField(required=False, allow_blank=True)
    receipt_file = serializers.FileField(required=False)  # Make optional initially

    class Meta:
        model = StudentPayment
        fields = [
            'payment_method_id', 'department_type', 'transaction_id',
            'amount', 'receipt_file', 'phone_number',
            'account_last_digits', 'note', 'payment_date',
            'clearance_form_id'
        ]
        read_only_fields = ['receipt_file']  # File will be handled separately

    def validate(self, data):
        # Validate payment method requirements
        try:
            payment_method = PaymentMethod.objects.get(id=data['payment_method_id'])
            
            if payment_method.name == 'telebirr' and not data.get('phone_number'):
                raise serializers.ValidationError({
                    "phone_number": "Phone number is required for Telebirr payments"
                })
            
            if payment_method.name == 'cbe' and not data.get('account_last_digits'):
                raise serializers.ValidationError({
                    "account_last_digits": "Account last 4 digits are required for CBE payments"
                })
            
        except PaymentMethod.DoesNotExist:
            raise serializers.ValidationError({
                "payment_method_id": "Invalid payment method"
            })
        
        # Validate clearance form if provided
        clearance_form_id = data.get('clearance_form_id')
        if clearance_form_id:
            try:
                clearance_form = ClearanceForm.objects.get(
                    id=clearance_form_id,
                    student=self.context['request'].user
                )
                data['clearance_form'] = clearance_form
                
                # Check if this form actually requires payment for this department
                required_status_map = {
                    'library': 'requires_library_payment',
                    'cafeteria': 'requires_cafeteria_payment',
                    'dormitory': 'requires_dormitory_payment'
                }
                
                required_status = required_status_map.get(data['department_type'])
                if required_status and clearance_form.status != required_status:
                    raise serializers.ValidationError({
                        'clearance_form_id': f'This form doesn\'t require {data["department_type"]} payment'
                    })
                    
            except ClearanceForm.DoesNotExist:
                raise serializers.ValidationError({
                    'clearance_form_id': 'Clearance form not found or access denied'
                })
        
        # Check for duplicate transaction ID
        if StudentPayment.objects.filter(transaction_id=data['transaction_id']).exists():
            raise serializers.ValidationError({
                'transaction_id': 'Transaction ID already exists'
            })
        
        return data

    def create(self, validated_data):
        # Extract payment_method_id and convert to PaymentMethod instance
        payment_method_id = validated_data.pop('payment_method_id')
        payment_method = PaymentMethod.objects.get(id=payment_method_id)
        
        # Extract clearance_form_id if provided
        clearance_form = validated_data.pop('clearance_form', None)
        
        # Create payment instance
        payment = StudentPayment.objects.create(
            student=self.context['request'].user,
            payment_method=payment_method,
            clearance_form=clearance_form,
            **validated_data
        )
        
        return payment

class PaymentVerificationSerializer(serializers.Serializer):
    """Serializer for verifying/rejecting payments"""
    action = serializers.ChoiceField(choices=['verify', 'reject'], required=True)
    note = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, data):
        if data['action'] == 'reject' and not data.get('note'):
            raise serializers.ValidationError({
                "note": "Rejection reason is required"
            })
        return data

class PaymentVerificationLogSerializer(serializers.ModelSerializer):
    verified_by_name = serializers.CharField(source='verified_by.get_full_name', read_only=True)
    
    class Meta:
        model = PaymentVerificationLog
        fields = ['id', 'verified_by', 'verified_by_name', 'action', 'note', 'created_at']


# In your serializers.py, add these serializers

class AuthorizedStudentSerializer(serializers.ModelSerializer):
    college_name = serializers.CharField(source='college.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    registered_username = serializers.CharField(source='registered_user.username', read_only=True)
    
    class Meta:
        model = AuthorizedStudent
        fields = [
            'id', 'first_name', 'last_name', 'id_number',
            'email', 'college', 'college_name', 'department', 'department_name',
            'is_active', 'is_registered', 'registered_user', 'registered_username',
            'registration_date', 'created_at'
        ]
        read_only_fields = ['email', 'college', 'department', 'is_registered', 'registered_user', 'registration_date']



class CSVUploadSerializer(serializers.ModelSerializer):
    uploaded_by_name = serializers.CharField(source='uploaded_by.get_full_name', read_only=True)
    
    class Meta:
        model = CSVStudentUpload
        fields = [
            'id', 'uploaded_by', 'uploaded_by_name', 'file', 'filename',
            'total_records', 'successful_records', 'failed_records',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['filename', 'total_records', 'successful_records', 'failed_records']
