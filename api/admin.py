from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import (
    User, College, Department, ClearanceForm, SystemControlRequest,
    FormAccessRequest, SystemControl, PasswordResetOTP,
    ClearanceFormStatusHistory, ClearanceFormResubmission,
    Notification, ChatRoom, Message, PaymentMethod,
    StudentPayment, PaymentVerificationLog
)
from django.utils import timezone

from .models import CSVStudentUpload, AuthorizedStudent

# ======== USER ========
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "username", "role", "is_blocked")
    list_filter = ("role", "is_blocked")
    search_fields = ("email", "username")
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)

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
    list_display = ('full_name', 'id_number', 'college', 'department_name', 'status', 'created_at')
    list_filter = ('status', 'college', 'department_name', 'year', 'semester')
    search_fields = ('full_name', 'id_number', 'college', 'department_name')
    ordering = ('-id',)

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

# # ======== SYSTEM CONTROL ========
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
    list_display = ('name', 'room_type', 'is_active', 'created_at')
    list_filter = ('room_type', 'is_active')
    search_fields = ('name', 'student__username')
    ordering = ('-created_at',)
    filter_horizontal = ('participants',)

# ======== MESSAGE ========
@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('room', 'sender', 'content_preview', 'is_read', 'created_at')
    list_filter = ('is_read', 'created_at')
    search_fields = ('content', 'sender__username', 'room__name')
    ordering = ('-created_at',)
    
    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
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
                'phone_number': '+251900000000',
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
        
        for method_data in default_methods:
            try:
                PaymentMethod.objects.get_or_create(
                    name=method_data['name'],
                    defaults=method_data
                )
            except IntegrityError:
                pass
        
        self.message_user(request, "Default payment methods initialized successfully!")

# ======== STUDENT PAYMENT ========
@admin.register(StudentPayment)
class StudentPaymentAdmin(admin.ModelAdmin):
    list_display = ('student', 'payment_method', 'department_type', 'amount', 'status', 'created_at')
    list_filter = ('status', 'department_type', 'payment_method')
    search_fields = ('student__username', 'student__email', 'transaction_id')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Payment Information', {
            'fields': ('student', 'payment_method', 'department_type', 'transaction_id', 'amount')
        }),
        ('Receipt Details', {
            'fields': ('receipt_file', 'receipt_thumbnail', 'phone_number', 'account_last_digits', 'payment_date')
        }),
        ('Verification', {
            'fields': ('status', 'verified_by', 'verified_at', 'rejection_reason')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

# ======== PAYMENT VERIFICATION LOG ========
@admin.register(PaymentVerificationLog)
class PaymentVerificationLogAdmin(admin.ModelAdmin):
    list_display = ('payment', 'verified_by', 'action', 'created_at')
    list_filter = ('action', 'created_at')
    search_fields = ('payment__transaction_id', 'verified_by__username', 'note')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)


@admin.register(CSVStudentUpload)
class CSVStudentUploadAdmin(admin.ModelAdmin):
    list_display = ('filename', 'uploaded_by', 'total_records', 'successful_records', 'failed_records', 'created_at')
    list_filter = ('created_at', 'uploaded_by')
    search_fields = ('filename', 'uploaded_by__username')
    readonly_fields = ('created_at', 'updated_at', 'total_records', 'successful_records', 'failed_records')
    
    # ADD ACTIONS
    actions = ['reprocess_csv', 'delete_with_students']
    
    @admin.action(description="Reprocess CSV file")
    def reprocess_csv(self, request, queryset):
        """Reprocess selected CSV files"""
        for csv_upload in queryset:
            print(f"Reprocessing: {csv_upload.filename}")
            # Delete existing students from this upload first
            deleted_count, _ = csv_upload.students.all().delete()
            print(f"Deleted {deleted_count} existing students")
            
            # Reprocess
            self.process_csv_file(csv_upload)
        
        self.message_user(request, f"Reprocessed {queryset.count()} CSV files")
    
    @admin.action(description="Delete with students")
    def delete_with_students(self, request, queryset):
        """Delete CSV upload and all associated students"""
        total_deleted = 0
        for csv_upload in queryset:
            # Count students
            student_count = csv_upload.students.count()
            # Delete students first
            deleted_count, _ = csv_upload.students.all().delete()
            # Delete the upload
            csv_upload.delete()
            total_deleted += student_count + 1  # +1 for the upload itself
        
        self.message_user(request, f"Deleted {queryset.count()} uploads and {total_deleted - queryset.count()} students")
    
    def save_model(self, request, obj, form, change):
        """Override save to process CSV file - FIXED VERSION"""
        # First save the model to get an ID
        super().save_model(request, obj, form, change)
        
        # Process CSV in the background using a signal or directly
        # We'll use a simple direct call for now
        try:
            self.process_csv_file(obj)
        except Exception as e:
            print(f"Error processing CSV: {e}")
            # Don't raise error, just log it
    
    def process_csv_file(self, csv_upload):
        """Process the CSV file and create authorized students - FIXED VERSION"""
        import csv
        import io
        from django.db import transaction
        
        print(f"\n{'='*60}")
        print(f"PROCESSING CSV FILE: {csv_upload.filename}")
        print(f"{'='*60}")
        
        try:
            # First, ensure the file is saved and accessible
            if not csv_upload.file:
                print("ERROR: No file attached to CSV upload")
                return
            
            # Open the file in read mode
            csv_file = csv_upload.file
            csv_file.open(mode='rb')  # Open in binary mode
            
            # Read the binary content
            raw_content = csv_file.read()
            csv_file.close()
            
            print(f"File size in bytes: {len(raw_content)}")
            
            if len(raw_content) == 0:
                print("ERROR: File is empty")
                return
            
            # Try different encodings to decode the content
            encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
            decoded_content = None
            used_encoding = None
            
            for encoding in encodings:
                try:
                    decoded_content = raw_content.decode(encoding)
                    used_encoding = encoding
                    print(f"✓ Successfully decoded with {encoding}")
                    break
                except UnicodeDecodeError:
                    continue
            
            if decoded_content is None:
                # Try with error handling
                try:
                    decoded_content = raw_content.decode('utf-8', errors='ignore')
                    used_encoding = 'utf-8 (with errors ignored)'
                    print(f"✓ Decoded with utf-8 (ignoring errors)")
                except:
                    print("ERROR: Could not decode CSV file with any encoding")
                    return
            
            # Clean the content - remove BOM if present
            if decoded_content.startswith('\ufeff'):
                decoded_content = decoded_content[1:]
                print("Removed UTF-8 BOM")
            
            print(f"Decoded content length: {len(decoded_content)} characters")
            print(f"First 300 chars:\n{decoded_content[:300]}")
            
            # Create a StringIO object for CSV reading
            csv_io = io.StringIO(decoded_content)
            
            # Try to detect CSV dialect
            try:
                sample = decoded_content[:1024]
                sniffer = csv.Sniffer()
                dialect = sniffer.sniff(sample)
                print(f"Detected CSV dialect: delimiter='{repr(dialect.delimiter)}', quotechar='{repr(dialect.quotechar)}'")
                csv_reader = csv.DictReader(csv_io, dialect=dialect)
            except Exception as e:
                print(f"Could not detect dialect, using default: {e}")
                # Reset and use default
                csv_io.seek(0)
                csv_reader = csv.DictReader(csv_io)
            
            if not csv_reader.fieldnames:
                print("ERROR: CSV has no headers or is empty after decoding")
                return
            
            print(f"Headers found: {csv_reader.fieldnames}")
            
            # Normalize headers (case-insensitive, spaces to underscores)
            header_map = {}
            for header in csv_reader.fieldnames:
                if header:  # Skip empty headers
                    normalized = header.strip().lower().replace(' ', '_').replace('-', '_').replace('.', '_')
                    header_map[normalized] = header
                    print(f"  '{header}' -> '{normalized}'")
            
            # Check required columns
            required = ['first_name', 'last_name', 'id_number']
            missing = []
            
            for req in required:
                if req not in header_map:
                    missing.append(req)
            
            if missing:
                print(f"ERROR: Missing required columns: {missing}")
                print(f"Available columns: {list(header_map.keys())}")
                return
            
            total_records = 0
            successful_records = 0
            failed_records = 0
            errors = []
            
            # Use transaction for atomic operations
            with transaction.atomic():
                # Clear existing students for this upload first
                deleted_count, _ = csv_upload.students.all().delete()
                print(f"Cleared {deleted_count} existing students")
                
                for row_num, row in enumerate(csv_reader, start=2):
                    total_records += 1
                    
                    try:
                        # Get values using original headers
                        first_name = row.get(header_map['first_name'], '').strip()
                        last_name = row.get(header_map['last_name'], '').strip()
                        id_number = row.get(header_map['id_number'], '').strip()
                        
                        if total_records <= 3:  # Debug first 3 rows
                            print(f"Row {row_num} (first 3 shown):")
                            print(f"  first_name: '{first_name}'")
                            print(f"  last_name: '{last_name}'")
                            print(f"  id_number: '{id_number}'")
                        
                        # Validate
                        if not first_name:
                            raise ValueError("First name is empty")
                        if not last_name:
                            raise ValueError("Last name is empty")
                        if not id_number:
                            raise ValueError("ID number is empty")
                        
                        # Check for duplicates in the database (not just this upload)
                        if AuthorizedStudent.objects.filter(id_number=id_number).exists():
                            existing = AuthorizedStudent.objects.get(id_number=id_number)
                            raise ValueError(f"ID '{id_number}' already exists for {existing.first_name} {existing.last_name}")
                        
                        # Create student
                        student = AuthorizedStudent.objects.create(
                            csv_upload=csv_upload,
                            first_name=first_name,
                            last_name=last_name,
                            id_number=id_number,
                            is_active=True,
                            is_registered=False
                        )
                        
                        successful_records += 1
                        
                    except Exception as e:
                        failed_records += 1
                        error_msg = f"Row {row_num}: {str(e)}"
                        errors.append(error_msg)
                        if failed_records <= 3:  # Show first 3 errors
                            print(f"  ✗ ERROR: {error_msg}")
                
                # Update counts on the CSV upload record
                csv_upload.total_records = total_records
                csv_upload.successful_records = successful_records
                csv_upload.failed_records = failed_records
                csv_upload.save()
                
                print(f"\n{'='*60}")
                print(f"PROCESSING COMPLETE")
                print(f"{'='*60}")
                print(f"Encoding used: {used_encoding}")
                print(f"Total rows in CSV: {total_records}")
                print(f"Successfully created: {successful_records}")
                print(f"Failed: {failed_records}")
                print(f"Total AuthorizedStudents in database: {AuthorizedStudent.objects.count()}")
                
                if errors:
                    print(f"\nFirst 5 errors:")
                    for error in errors[:5]:
                        print(f"  - {error}")
                
        except Exception as e:
            print(f"\n{'='*60}")
            print(f"FATAL ERROR processing CSV: {str(e)}")
            print(f"{'='*60}")
            import traceback
            traceback.print_exc()
            
            # Update counts with error info
            csv_upload.total_records = 0
            csv_upload.successful_records = 0
            csv_upload.failed_records = 1
            csv_upload.save()


@admin.register(AuthorizedStudent)
class AuthorizedStudentAdmin(admin.ModelAdmin):
    list_display = ('get_full_name', 'id_number', 'is_active', 'is_registered', 'email', 'college', 'department', 'created_at')
    list_filter = ('is_active', 'is_registered', 'college', 'department', 'created_at')
    search_fields = ('first_name', 'last_name', 'id_number')
    readonly_fields = ('is_registered', 'registered_user', 'registration_date', 'created_at', 'updated_at')
    
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
            'fields': ('csv_upload',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def has_delete_permission(self, request, obj=None):
        # Prevent deletion if student is already registered
        if obj and obj.is_registered:
            return False
        return True