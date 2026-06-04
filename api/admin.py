from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import (
    User, College, Department, ClearanceForm, SystemControlRequest,
    FormAccessRequest, SystemControl, PasswordResetOTP,
    ClearanceFormStatusHistory, ClearanceFormResubmission,
    Notification, ChatRoom, Message, PaymentMethod,
    StudentPayment, PaymentVerificationLog, Building,
    CSVStudentUpload, AuthorizedStudent
)
from django.utils import timezone
from django.db.models import Count
from django.urls import reverse
from django.utils.html import format_html
from django.http import HttpResponse
import csv
import io
from django.db import transaction

# ======== USER ========
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "username", "role", "building_info", "assigned_buildings_list", "is_blocked")
    list_filter = ("role", "is_blocked", "building", "assigned_buildings")
    search_fields = ("email", "username", "first_name", "last_name")
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)
    filter_horizontal = ('assigned_buildings',)
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('username', 'email', 'password', 'first_name', 'last_name')
        }),
        ('Role & Status', {
            'fields': ('role', 'is_blocked', 'is_active', 'is_staff', 'is_superuser')
        }),
        ('Academic Information', {
            'fields': ('id_number', 'college', 'department'),
            'classes': ('collapse',)
        }),
        ('Building Assignment', {
            'fields': ('building', 'assigned_buildings'),
            'description': """
                <strong>For Students:</strong> Select their residential building from the "Building" dropdown.<br>
                <strong>For Dormitory Staff:</strong> Select all buildings they manage using the "Assigned buildings" multi-select.
            """,
            'classes': ('wide',)
        }),
        ('Profile', {
            'fields': ('phone', 'profile_picture'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'last_login', 'date_joined'),
            'classes': ('collapse',)
        })
    )
    
    def building_info(self, obj):
        if obj.building:
            return format_html(
                '<strong>{}</strong><br><small style="color: #666;">{}</small>',
                obj.building.name,
                obj.building.code
            )
        return '-'
    building_info.short_description = "Residence Building"
    
    def assigned_buildings_list(self, obj):
        buildings = obj.assigned_buildings.all()
        if buildings:
            return format_html(
                ', '.join([
                    f'<span style="background: #e6f7ff; padding: 2px 5px; border-radius: 3px;">{b.name}</span>'
                    for b in buildings[:3]
                ]) + (' +{} more'.format(buildings.count() - 3) if buildings.count() > 3 else '')
            )
        return '-'
    assigned_buildings_list.short_description = "Manages Buildings"
    
    actions = ['assign_buildings_to_selected']
    
    @admin.action(description="Assign buildings to selected dormitory staff")
    def assign_buildings_to_selected(self, request, queryset):
        """Bulk assign buildings to dormitory staff"""
        from django.contrib import messages
        
        # Filter only dormitory staff
        dorm_staff = queryset.filter(role='dormitory')
        
        if not dorm_staff.exists():
            self.message_user(request, "No dormitory staff selected.", level='ERROR')
            return
        
        # This will be handled by a custom intermediate page in a real implementation
        # For now, just show a message
        self.message_user(
            request, 
            f"Selected {dorm_staff.count()} dormitory staff. Please use the individual user edit form to assign buildings.",
            level='WARNING'
        )
        
        
        # In your UserAdmin class, add this method
def save_model(self, request, obj, form, change):
    """Ensure only one department head per department"""
    
    # Check if this user is being assigned as department head
    if obj.role == 'departmenthead' and obj.department:
        # Check if there's already another department head for this department
        existing_head = User.objects.filter(
            role='departmenthead',
            department=obj.department
        ).exclude(pk=obj.pk).first()
        
        if existing_head:
            from django.contrib import messages
            self.message_user(
                request,
                f"Department '{obj.department.name}' already has a department head: {existing_head.username}. "
                f"Please remove that assignment first.",
                level='ERROR'
            )
            return False  # Prevent save
    
    super().save_model(request, obj, form, change)
    return True

# ======== COLLEGE ========
@admin.register(College)
class CollegeAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)
    ordering = ('name',)

# ======== DEPARTMENT ========
@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "college", "head_email")
    list_filter = ('college',)
    search_fields = ('name', 'college__name', 'head_email')
    ordering = ('college', 'name')

# ======== CLEARANCE FORM ========
@admin.register(ClearanceForm)
class ClearanceFormAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'id_number', 'college', 'department_name', 'status', 'building_info', 'created_at')
    list_filter = ('status', 'college', 'department_name', 'year', 'semester', 'student_building')
    search_fields = ('full_name', 'id_number', 'college', 'department_name')
    ordering = ('-id',)
    raw_id_fields = ('student', 'student_building')
    
    def building_info(self, obj):
        if obj.student_building:
            return format_html(
                '{}<br><small>{}</small>',
                obj.student_building.name,
                obj.student_building.code
            )
        return '-'
    building_info.short_description = "Building"

# ======== SYSTEM CONTROL REQUEST ========
@admin.register(SystemControlRequest)
class SystemControlRequestAdmin(admin.ModelAdmin):
    list_display = ('email', 'status', 'reason', 'created_at')
    list_filter = ('status',)
    search_fields = ('email', 'reason')
    ordering = ('-created_at',)

# ======== FORM ACCESS REQUEST ========
@admin.register(FormAccessRequest)
class FormAccessRequestAdmin(admin.ModelAdmin):
    list_display = ('student_name', 'email', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('student_name', 'email')
    ordering = ('-created_at',)

# ======== SYSTEM CONTROL ========
@admin.register(SystemControl)
class SystemControlAdmin(admin.ModelAdmin):
    list_display = ('is_open', 'open_time', 'close_time', 'created_at')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('System Status', {
            'fields': ('is_open', 'open_time', 'close_time'),
            'description': 'Set whether the system is open or closed and specify open/close times.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def save_model(self, request, obj, form, change):
        """
        Ensure only one SystemControl record exists,
        and handle open/close timestamps automatically.
        """
        if not change:  # Creating new
            if SystemControl.objects.exists():
                raise Exception("A SystemControl record already exists. You cannot create another.")
        
        # Automatically set open/close times if needed
        if obj.is_open and not obj.open_time:
            obj.open_time = timezone.now()
            obj.close_time = None  # Reset close time if reopening
        elif not obj.is_open and not obj.close_time:
            obj.close_time = timezone.now()
        
        super().save_model(request, obj, form, change)

    def has_add_permission(self, request):
        """Prevent adding more than one SystemControl record"""
        return not SystemControl.objects.exists()

    def has_delete_permission(self, request, obj=None):
        """Prevent deleting the SystemControl record"""
        return False

# ======== PASSWORD RESET OTP ========
@admin.register(PasswordResetOTP)
class PasswordResetOTPAdmin(admin.ModelAdmin):
    list_display = ('email', 'otp', 'is_used', 'created_at')
    list_filter = ('is_used',)
    search_fields = ('email', 'otp')
    ordering = ('-created_at',)

# ======== CLEARANCE FORM STATUS HISTORY ========
@admin.register(ClearanceFormStatusHistory)
class ClearanceFormStatusHistoryAdmin(admin.ModelAdmin):
    list_display = ('form', 'status', 'changed_by', 'changed_at')
    list_filter = ('status',)
    search_fields = ('form__full_name', 'form__id_number', 'note')
    ordering = ('-changed_at',)
    readonly_fields = ('changed_at',)

# ======== CLEARANCE FORM RESUBMISSION ========
@admin.register(ClearanceFormResubmission)
class ClearanceFormResubmissionAdmin(admin.ModelAdmin):
    list_display = ('original_form', 'resubmitted_form', 'resubmitted_by', 'resubmitted_at')
    search_fields = ('original_form__full_name', 'resubmitted_form__full_name', 'reason')
    ordering = ('-resubmitted_at',)
    readonly_fields = ('resubmitted_at',)

# ======== NOTIFICATION ========
@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'title', 'is_read', 'created_at')
    list_filter = ('is_read',)
    search_fields = ('user__username', 'title', 'message')
    ordering = ('-created_at',)

# ======== CHAT ROOM ========
@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ('name', 'room_type', 'student', 'specific_staff', 'is_active', 'created_at')
    list_filter = ('room_type', 'is_active')
    search_fields = ('name', 'student__username', 'specific_staff__username')
    ordering = ('-created_at',)
    filter_horizontal = ('participants',)
    raw_id_fields = ('student', 'specific_staff', 'department')

# ======== MESSAGE ========
@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('room', 'sender', 'content_preview', 'is_read', 'created_at')
    list_filter = ('is_read', 'created_at', 'message_type')
    search_fields = ('content', 'sender__username', 'room__name')
    ordering = ('-created_at',)
    raw_id_fields = ('room', 'sender', 'reply_to')
    
    def content_preview(self, obj):
        if obj.content and len(obj.content) > 50:
            return obj.content[:50] + '...'
        return obj.content or f"[{obj.message_type}]"
    content_preview.short_description = 'Content'

# ======== PAYMENT METHOD ========
@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = ('name', 'account_name', 'account_number', 'phone_number', 'is_active', 'created_at')
    list_filter = ('is_active', 'name')
    search_fields = ('name', 'account_name', 'account_number', 'phone_number')
    ordering = ('name',)
    actions = ['initialize_payment_methods']

    @admin.action(description="Initialize default payment methods")
    def initialize_payment_methods(self, request, queryset):
        from django.db import IntegrityError
        
        default_methods = [
            {
                'name': 'telebirr',
                'account_number': '',
                'phone_number': '+251911111111',
                'account_name': 'University Name',
                'instructions': 'Send payment via Telebirr to the phone number above. Include your ID number in the reference.'
            },
            {
                'name': 'cbe',
                'account_number': '1000000000000',
                'phone_number': '',
                'account_name': 'University Name',
                'instructions': 'Transfer to the CBE account above. Include your ID number in the reference.'
            }
        ]
        
        created_count = 0
        for method_data in default_methods:
            try:
                obj, created = PaymentMethod.objects.get_or_create(
                    name=method_data['name'],
                    defaults=method_data
                )
                if created:
                    created_count += 1
            except IntegrityError:
                pass
        
        self.message_user(request, f"Created {created_count} default payment methods successfully!")

# ======== STUDENT PAYMENT ========
@admin.register(StudentPayment)
class StudentPaymentAdmin(admin.ModelAdmin):
    list_display = ('student', 'payment_method', 'department_type', 'amount', 'status', 'created_at')
    list_filter = ('status', 'department_type', 'payment_method', 'created_at')
    search_fields = ('student__username', 'student__email', 'transaction_id')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at', 'receipt_thumbnail_preview')
    raw_id_fields = ('student', 'clearance_form', 'verified_by', 'payment_method')
    
    fieldsets = (
        ('Payment Information', {
            'fields': ('student', 'payment_method', 'department_type', 'transaction_id', 'amount')
        }),
        ('Clearance Form', {
            'fields': ('clearance_form',),
            'classes': ('collapse',)
        }),
        ('Receipt Details', {
            'fields': ('receipt_file', 'receipt_thumbnail_preview', 'phone_number', 'account_last_digits', 'payment_date', 'note')
        }),
        ('Verification', {
            'fields': ('status', 'verified_by', 'verified_at', 'rejection_reason')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def receipt_thumbnail_preview(self, obj):
        if obj.receipt_thumbnail:
            return format_html('<img src="{}" style="max-height: 100px; max-width: 100px;" />', obj.receipt_thumbnail.url)
        elif obj.receipt_file:
            return format_html('<a href="{}" target="_blank">View Receipt</a>', obj.receipt_file.url)
        return "No receipt"
    receipt_thumbnail_preview.short_description = 'Receipt Preview'

# ======== PAYMENT VERIFICATION LOG ========
@admin.register(PaymentVerificationLog)
class PaymentVerificationLogAdmin(admin.ModelAdmin):
    list_display = ('payment', 'verified_by', 'action', 'created_at')
    list_filter = ('action', 'created_at')
    search_fields = ('payment__transaction_id', 'verified_by__username', 'note')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)
    raw_id_fields = ('payment', 'verified_by')

# ======== CSV STUDENT UPLOAD ========
@admin.register(CSVStudentUpload)
class CSVStudentUploadAdmin(admin.ModelAdmin):
    list_display = ('filename', 'uploaded_by', 'total_records', 'successful_records', 'failed_records', 'created_at')
    list_filter = ('created_at', 'uploaded_by')
    search_fields = ('filename', 'uploaded_by__username')
    readonly_fields = ('created_at', 'updated_at', 'total_records', 'successful_records', 'failed_records', 'csv_preview')
    
    fieldsets = (
        ('Upload Information', {
            'fields': ('uploaded_by', 'file', 'filename')
        }),
        ('Processing Results', {
            'fields': ('total_records', 'successful_records', 'failed_records', 'csv_preview')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def csv_preview(self, obj):
        """Preview the first few lines of the CSV file"""
        if not obj.file:
            return "No file uploaded"
        
        try:
            obj.file.open(mode='rb')
            content = obj.file.read(500)  # Read first 500 bytes
            obj.file.close()
            
            # Try to decode
            try:
                text = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text = content.decode('latin-1')
                except:
                    text = "Could not decode preview"
            
            return format_html('<pre style="max-height: 200px; overflow: auto;">{}</pre>', text)
        except Exception as e:
            return f"Error reading file: {e}"
    csv_preview.short_description = 'CSV Preview'
    
    actions = ['reprocess_csv', 'delete_with_students']
    
    @admin.action(description="Reprocess selected CSV files")
    def reprocess_csv(self, request, queryset):
        """Reprocess selected CSV files"""
        processed = 0
        for csv_upload in queryset:
            try:
                # Delete existing students from this upload first
                deleted_count, _ = csv_upload.students.all().delete()
                
                # Reprocess
                success = self.process_csv_file(csv_upload)
                if success:
                    processed += 1
                    self.message_user(request, f"Reprocessed {csv_upload.filename}: {csv_upload.successful_records} records")
            except Exception as e:
                self.message_user(request, f"Error processing {csv_upload.filename}: {e}", level='ERROR')
        
        self.message_user(request, f"Successfully reprocessed {processed} of {queryset.count()} CSV files")
    
    @admin.action(description="Delete with associated students")
    def delete_with_students(self, request, queryset):
        """Delete CSV upload and all associated students"""
        total_deleted = 0
        total_students = 0
        
        for csv_upload in queryset:
            student_count = csv_upload.students.count()
            # Delete students first
            deleted_students, _ = csv_upload.students.all().delete()
            total_students += deleted_students
            # Delete the upload
            csv_upload.delete()
            total_deleted += 1
        
        self.message_user(
            request, 
            f"Deleted {total_deleted} uploads and {total_students} associated students"
        )
    
    def process_csv_file(self, csv_upload):
        """Process the CSV file and create authorized students"""
        import csv
        
        try:
            # Open the file
            if not csv_upload.file:
                return False
            
            csv_upload.file.open(mode='rb')
            raw_content = csv_upload.file.read()
            csv_upload.file.close()
            
            if len(raw_content) == 0:
                return False
            
            # Try different encodings
            encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
            decoded_content = None
            
            for encoding in encodings:
                try:
                    decoded_content = raw_content.decode(encoding)
                    break
                except UnicodeDecodeError:
                    continue
            
            if decoded_content is None:
                decoded_content = raw_content.decode('utf-8', errors='ignore')
            
            # Remove BOM if present
            if decoded_content.startswith('\ufeff'):
                decoded_content = decoded_content[1:]
            
            # Create CSV reader
            csv_io = io.StringIO(decoded_content)
            csv_reader = csv.DictReader(csv_io)
            
            if not csv_reader.fieldnames:
                return False
            
            # Normalize headers
            header_map = {}
            for header in csv_reader.fieldnames:
                if header:
                    normalized = header.strip().lower().replace(' ', '_').replace('-', '_')
                    header_map[normalized] = header
            
            # Check required columns
            required = ['first_name', 'last_name', 'id_number']
            missing = [req for req in required if req not in header_map]
            
            if missing:
                return False
            
            total_records = 0
            successful_records = 0
            failed_records = 0
            
            with transaction.atomic():
                # Clear existing students
                csv_upload.students.all().delete()
                
                for row in csv_reader:
                    total_records += 1
                    
                    try:
                        first_name = row.get(header_map['first_name'], '').strip()
                        last_name = row.get(header_map['last_name'], '').strip()
                        id_number = row.get(header_map['id_number'], '').strip()
                        
                        if not first_name or not last_name or not id_number:
                            failed_records += 1
                            continue
                        
                        # Check for duplicates in database
                        if not AuthorizedStudent.objects.filter(id_number=id_number).exists():
                            AuthorizedStudent.objects.create(
                                csv_upload=csv_upload,
                                first_name=first_name,
                                last_name=last_name,
                                id_number=id_number,
                                is_active=True,
                                is_registered=False
                            )
                            successful_records += 1
                        else:
                            failed_records += 1
                            
                    except Exception:
                        failed_records += 1
                
                # Update counts
                csv_upload.total_records = total_records
                csv_upload.successful_records = successful_records
                csv_upload.failed_records = failed_records
                csv_upload.save()
                
            return True
            
        except Exception as e:
            print(f"Error processing CSV: {e}")
            return False

# ======== AUTHORIZED STUDENT ========
@admin.register(AuthorizedStudent)
class AuthorizedStudentAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'id_number', 'is_active', 'is_registered', 'email', 'college_name', 'department_name', 'created_at')
    list_filter = ('is_active', 'is_registered', 'college', 'department', 'created_at')
    search_fields = ('first_name', 'last_name', 'id_number', 'email')
    readonly_fields = ('is_registered', 'registered_user', 'registration_date', 'created_at', 'updated_at', 'csv_upload_link')
    raw_id_fields = ('college', 'department', 'registered_user')
    
    fieldsets = (
        ('Required Authorization Fields', {
            'fields': ('first_name', 'last_name', 'id_number'),
            'description': 'These 3 fields are required for authorization. Students must match these exactly.'
        }),
        ('Registration Information (Auto-filled during registration)', {
            'fields': ('email', 'college', 'department')
        }),
        ('Registration Status', {
            'fields': ('is_active', 'is_registered', 'registered_user', 'registration_date')
        }),
        ('Upload Information', {
            'fields': ('csv_upload_link',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"
    full_name.short_description = 'Name'
    full_name.admin_order_field = 'first_name'
    
    def college_name(self, obj):
        return obj.college.name if obj.college else '-'
    college_name.short_description = 'College'
    college_name.admin_order_field = 'college__name'
    
    def department_name(self, obj):
        return obj.department.name if obj.department else '-'
    department_name.short_description = 'Department'
    department_name.admin_order_field = 'department__name'
    
    def csv_upload_link(self, obj):
        if obj.csv_upload:
            url = reverse('admin:api_csvstudentupload_change', args=[obj.csv_upload.id])
            return format_html('<a href="{}">{}</a>', url, obj.csv_upload.filename)
        return '-'
    csv_upload_link.short_description = 'Source CSV'
    
    def has_delete_permission(self, request, obj=None):
        # Prevent deletion if student is already registered
        if obj and obj.is_registered:
            return False
        return True
    
    actions = ['activate_selected', 'deactivate_selected']
    
    @admin.action(description="Activate selected students")
    def activate_selected(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} student(s) activated successfully.")
    
    @admin.action(description="Deactivate selected students")
    def deactivate_selected(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} student(s) deactivated successfully.")

# ======== BUILDING MANAGEMENT ========
@admin.register(Building)
class BuildingAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'capacity', 'current_occupancy', 'assigned_staff_count', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'code', 'address')
    ordering = ('name',)
    
    # Add custom methods to readonly_fields so they can be used in fieldsets
    readonly_fields = ('created_at', 'student_list', 'staff_list', 'form_list', 
                      'occupancy_percentage', 'current_occupancy', 'assigned_staff_count')
    
    fieldsets = (
        ('Building Information', {
            'fields': ('name', 'code', 'address', 'capacity', 'is_active')
        }),
        ('Statistics', {
            'fields': ('current_occupancy', 'occupancy_percentage', 'assigned_staff_count', 
                      'student_list', 'staff_list', 'form_list'),
            'classes': ('wide',)
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        from django.db.models import Count
        
        queryset = super().get_queryset(request)
        queryset = queryset.annotate(
            student_count=Count('building_students', distinct=True),
            staff_count=Count('assigned_staff', distinct=True),
            form_count=Count('form_buildings', distinct=True)
        )
        return queryset
    
    def current_occupancy(self, obj):
        student_count = obj.building_students.filter(is_active=True).count()
        
        # Convert to integer for calculation
        student_count_int = int(student_count)
        capacity_int = int(obj.capacity) if obj.capacity else 0
        
        if capacity_int > 0:
            percentage = (student_count_int / capacity_int) * 100
            
            # Determine color based on percentage
            if percentage < 80:
                color = 'green'
            elif percentage < 95:
                color = 'orange'
            else:
                color = 'red'
            
            # Format the percentage as a string to avoid SafeString issues
            percentage_str = f"{percentage:.1f}"
            
            from django.utils.html import format_html
            return format_html(
                '{} / {}<br><span style="color: {};">({}%)</span>',
                student_count_int,
                capacity_int,
                color,
                percentage_str
            )
        return f"{student_count_int} / Unlimited"
    current_occupancy.short_description = "Occupancy"
    
    def assigned_staff_count(self, obj):
        return obj.assigned_staff.count()
    assigned_staff_count.short_description = "Staff Count"
    assigned_staff_count.admin_order_field = 'staff_count'
    
    def occupancy_percentage(self, obj):
        student_count = obj.building_students.filter(is_active=True).count()
        student_count_int = int(student_count)
        capacity_int = int(obj.capacity) if obj.capacity else 0
        
        if capacity_int > 0:
            percentage = (student_count_int / capacity_int) * 100
            return f"{percentage:.1f}%"
        return "N/A"
    occupancy_percentage.short_description = "Occupancy %"
    
    def student_list(self, obj):
        from django.urls import reverse
        from django.utils.html import format_html
        
        url = reverse('admin:api_user_changelist') + f'?building__id__exact={obj.id}'
        count = obj.building_students.count()
        return format_html('<a href="{}">View {} Student(s)</a>', url, count)
    student_list.short_description = 'Students'
    
    def staff_list(self, obj):
        from django.urls import reverse
        from django.utils.html import format_html
        
        url = reverse('admin:api_user_changelist') + f'?assigned_buildings__id__exact={obj.id}'
        count = obj.assigned_staff.count()
        return format_html('<a href="{}">View {} Staff Member(s)</a>', url, count)
    staff_list.short_description = 'Assigned Staff'
    
    def form_list(self, obj):
        from django.urls import reverse
        from django.utils.html import format_html
        
        url = reverse('admin:api_clearanceform_changelist') + f'?student_building__id__exact={obj.id}'
        count = obj.form_buildings.count()
        return format_html('<a href="{}">View {} Clearance Form(s)</a>', url, count)
    form_list.short_description = 'Forms'
    
    actions = ['activate_buildings', 'deactivate_buildings', 'export_building_stats']
    
    @admin.action(description="Activate selected buildings")
    def activate_buildings(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} building(s) activated successfully.")
    
    @admin.action(description="Deactivate selected buildings")
    def deactivate_buildings(self, request, queryset):
        # Check if buildings have active students before deactivating
        can_deactivate = []
        cannot_deactivate = []
        
        for building in queryset:
            if building.building_students.filter(is_active=True).exists():
                cannot_deactivate.append(building.name)
            else:
                can_deactivate.append(building.id)
        
        if can_deactivate:
            updated = Building.objects.filter(id__in=can_deactivate).update(is_active=False)
            self.message_user(request, f"{updated} building(s) deactivated successfully.")
        
        if cannot_deactivate:
            self.message_user(
                request, 
                f"Cannot deactivate these buildings (they have active students): {', '.join(cannot_deactivate)}",
                level='WARNING'
            )
    
    @admin.action(description="Export building statistics to CSV")
    def export_building_stats(self, request, queryset):
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="building_statistics.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Building Name', 'Code', 'Capacity', 'Current Students', 
            'Assigned Staff', 'Pending Forms', 'Active', 'Created Date'
        ])
        
        for building in queryset:
            writer.writerow([
                building.name,
                building.code,
                building.capacity if building.capacity > 0 else 'Unlimited',
                building.building_students.filter(is_active=True).count(),
                building.assigned_staff.count(),
                building.form_buildings.filter(status='approved_studentaffairs').count(),
                'Yes' if building.is_active else 'No',
                building.created_at.strftime('%Y-%m-%d') if building.created_at else 'N/A'
            ])
        
        return response