from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from PIL import Image
from django.utils import timezone
from django.conf import settings
from django.core.validators import FileExtensionValidator
class College(models.Model):
    name = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    college = models.ForeignKey(College, on_delete=models.CASCADE, null=True, blank=True)
    head_email = models.EmailField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(username, email, password, **extra_fields)

class User(AbstractUser):
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('departmenthead', 'Department Head'),
        ('librarian', 'Librarian'),
        ('cafeteria', 'Cafeteria'),
        ('dormitory', 'Dormitory'),
        ('registrar', 'Registrar'),
        ('admin', 'Admin'),
    ]

    role = models.CharField(max_length=30, choices=ROLE_CHOICES)
    phone = models.CharField(max_length=20, blank=True, null=True, verbose_name='Phone Number')
    id_number = models.CharField(max_length=20, blank=True, null=True)
    college = models.CharField(max_length=100, blank=True, null=True)
    department = models.ForeignKey(
        "Department",
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    created_at = models.DateTimeField(default=timezone.now)
    
    # Profile fields
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True, verbose_name='Profile Picture')
    last_password_change = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Last Password Change'
    )
    password_reset_required = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
    is_blocked = models.BooleanField(default=False)


    def get_profile_picture_url(self):
        """Get profile picture URL or default avatar"""
        if self.profile_picture:
            return self.profile_picture.url
        # Generate default avatar using UI Avatars API
        name = self.get_full_name() or self.username
        return f"https://ui-avatars.com/api/?name={name.replace(' ', '+')}&background=random&color=fff&size=150"
    
    def create_thumbnail(self):
        """Create thumbnail for profile picture - optional"""
        try:
            from PIL import Image
            import os
            from io import BytesIO
            from django.core.files.base import ContentFile
            
            if self.profile_picture:
                # Open image
                img = Image.open(self.profile_picture)
                
                # Resize image
                output_size = (150, 150)
                img.thumbnail(output_size, Image.Resampling.LANCZOS)
                
                # Save thumbnail in memory
                thumb_io = BytesIO()
                
                # Determine format
                if img.format == 'PNG':
                    img.save(thumb_io, format='PNG')
                    extension = 'png'
                else:
                    img = img.convert('RGB')
                    img.save(thumb_io, format='JPEG', quality=85)
                    extension = 'jpg'
                
                # Generate filename
                thumb_name = f"thumb_{os.path.basename(self.profile_picture.name)}"
                
                # Save the thumbnail
                from django.core.files.base import ContentFile
                self.profile_picture.save(
                    thumb_name,
                    ContentFile(thumb_io.getvalue()),
                    save=False
                )
        except Exception as e:
            print(f"Error creating thumbnail: {e}")
    
    def save(self, *args, **kwargs):
        # Call parent save
        super().save(*args, **kwargs)
        
        # Optional: Create thumbnail after saving
        if self.profile_picture and not self.pk:
            try:
                self.create_thumbnail()
            except:
                pass

    REQUIRED_FIELDS = ['email', 'role']
    USERNAME_FIELD = 'username'

    def save(self, *args, **kwargs):
        self.is_active = not self.is_blocked
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.username} ({self.role})"

    def get_full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    class Meta:
        ordering = ['-date_joined']

# ======================================================
# CLEARANCE FORM
# ======================================================

class ClearanceForm(models.Model):
    PROGRAM_LEVEL_CHOICES = [
        ("Undergraduate", "Undergraduate"),
        ("Graduate", "Graduate"),
        ("Postgraduate", "Postgraduate"),
    ]

    ENROLLMENT_TYPE_CHOICES = [
        ("Regular Full Time", "Regular Full Time"),
        ("Regular Part Time", "Regular Part Time"),
        ("Extension", "Extension"),
        ("Summer", "Summer"),
        ("Distance Education", "Distance Education"),
    ]

    YEAR_CHOICES = [(str(i), str(i)) for i in range(1, 9)]
    SEMESTER_CHOICES = [("I", "I"), ("II", "II")]

    STATUS_CHOICES = [
        ('pending_department', 'Pending Department'),
        ('approved_department', 'Approved by Department'),
        ('approved_library', 'Approved by Library'),
        ('approved_cafeteria', 'Approved by Cafeteria'),
        ('approved_dormitory', 'Approved by Dormitory'),
        ('Cleared by Registrar', 'Cleared by Registrar'),
        ('rejected', 'Rejected'),
        ('pending_resubmission', 'Pending Resubmission'),

        ('requires_library_payment', 'Requires Library Payment'),
        ('requires_cafeteria_payment', 'Requires Cafeteria Payment'),
        ('requires_dormitory_payment', 'Requires Dormitory Payment'),
    ]

    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="clearance_forms"
    )

    full_name = models.CharField(max_length=255)
    id_number = models.CharField(max_length=50)
    academic_year = models.CharField(max_length=20)
    program_level = models.CharField(max_length=20, choices=PROGRAM_LEVEL_CHOICES)
    enrollment_type = models.CharField(max_length=30, choices=ENROLLMENT_TYPE_CHOICES)
    college = models.CharField(max_length=255)
    department_name = models.CharField(max_length=255)
    section = models.CharField(max_length=50)
    last_attendance = models.DateField()
    year = models.CharField(max_length=5, choices=YEAR_CHOICES)
    semester = models.CharField(max_length=5, choices=SEMESTER_CHOICES)
    reason = models.TextField()

    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="pending_department")

    # Department notes
    department_note = models.TextField(blank=True, null=True)
    library_note = models.TextField(blank=True, null=True)
    cafeteria_note = models.TextField(blank=True, null=True)
    dormitory_note = models.TextField(blank=True, null=True)
    registrar_note = models.TextField(blank=True, null=True)
    # Department
    department_approved_by = models.CharField(max_length=255, null=True, blank=True)
    department_approved_at = models.DateTimeField(null=True, blank=True)

# Library
    library_approved_by = models.CharField(max_length=255, null=True, blank=True)
    library_approved_at = models.DateTimeField(null=True, blank=True)

# Cafeteria
    cafeteria_approved_by = models.CharField(max_length=255, null=True, blank=True)
    cafeteria_approved_at = models.DateTimeField(null=True, blank=True)

# Dormitory
    dormitory_approved_by = models.CharField(max_length=255, null=True, blank=True)
    dormitory_approved_at = models.DateTimeField(null=True, blank=True)

# Registrar
    registrar_approved_by = models.CharField(max_length=255, null=True, blank=True)
    registrar_approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    cleared_at = models.DateTimeField(null=True, blank=True)
    

    def __str__(self):
        return f"{self.full_name} - {self.id_number}"

class ClearanceCertificate(models.Model):
    certificate_id = models.CharField(max_length=100, unique=True)
    clearance_form = models.OneToOneField(
        ClearanceForm,
        on_delete=models.CASCADE,
        related_name="certificate"
    )
    issued_at = models.DateTimeField(auto_now_add=True)
    is_valid = models.BooleanField(default=True)

    def __str__(self):
        return self.certificate_id


class FormAccessRequest(models.Model):
    student_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    status = models.CharField(max_length=20, default="Pending")
    reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.student_name} - {self.status}"


# ======================================================
# SYSTEM CONTROL MODELS
# ======================================================

class SystemControl(models.Model):
    is_open = models.BooleanField(default=True, verbose_name="System Open")
    open_time = models.DateTimeField(null=True, blank=True)
    close_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Individual module controls
    is_department_head_open = models.BooleanField(default=True, verbose_name="Department Head Module")
    is_librarian_open = models.BooleanField(default=True, verbose_name="Librarian Module")
    is_cafeteria_open = models.BooleanField(default=True, verbose_name="Cafeteria Module")
    is_dormitory_open = models.BooleanField(default=True, verbose_name="Dormitory Module")
    is_registrar_open = models.BooleanField(default=True, verbose_name="Registrar Module")
    is_student_open = models.BooleanField(default=True, verbose_name="Student Module")
    is_payment_open = models.BooleanField(default=True, verbose_name="Payment Module")
    
    # Maintenance settings
    show_maintenance_page = models.BooleanField(default=True)
    maintenance_title = models.CharField(max_length=200, blank=True, null=True)
    maintenance_message = models.TextField(blank=True, null=True)
    
    # Scheduled maintenance
    scheduled_maintenance_start = models.DateTimeField(null=True, blank=True)
    scheduled_maintenance_end = models.DateTimeField(null=True, blank=True)
    scheduled_maintenance_message = models.TextField(blank=True, null=True)

    def save(self, *args, **kwargs):
        # Ensure singleton
        if not self.pk and SystemControl.objects.exists():
            raise ValueError("Only one SystemControl instance allowed")
        super().save(*args, **kwargs)

    @classmethod
    def get_status(cls):
        """Get system status"""
        obj = cls.objects.first()
        if obj:
            return obj.is_open
        return True  # default open

    @classmethod
    def get_module_status(cls, module_name):
        """Get specific module status"""
        obj = cls.objects.first()
        if not obj:
            return True  # default open
        
        if not obj.is_open:
            return False  # If system closed, all modules closed
        
        module_map = {
            'departmenthead': 'is_department_head_open',
            'librarian': 'is_librarian_open',
            'cafeteria': 'is_cafeteria_open',
            'dormitory': 'is_dormitory_open',
            'registrar': 'is_registrar_open',
            'student': 'is_student_open',
            'payment': 'is_payment_open',
        }
        
        field_name = module_map.get(module_name)
        if field_name:
            return getattr(obj, field_name, True)
        return True

    def __str__(self):
        status = "OPEN" if self.is_open else "CLOSED"
        return f"System: {status} | Modules: {' | '.join([f'{k}:{v}' for k, v in self.get_module_statuses().items()])}"

    def get_module_statuses(self):
        """Get all module statuses"""
        return {
            'departmenthead': self.is_department_head_open,
            'librarian': self.is_librarian_open,
            'cafeteria': self.is_cafeteria_open,
            'dormitory': self.is_dormitory_open,
            'registrar': self.is_registrar_open,
            'student': self.is_student_open,
            'payment': self.is_payment_open,
        }


class SystemControlRequest(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected")
    ]
    email = models.EmailField(unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.email} - {self.status}"
# ======================================================
# PASSWORD RESET
# ======================================================

class PasswordResetOTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    verification_token = models.CharField(max_length=100, blank=True, null=True)
    is_used = models.BooleanField(default=False)
    is_password_reset = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def __str__(self):
        return f"{self.email} - {self.otp}"
    
    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at

# ======================================================
# CLEARANCE FORM STATUS HISTORY
# ======================================================

class ClearanceFormStatusHistory(models.Model):
    form = models.ForeignKey(
        ClearanceForm,
        on_delete=models.CASCADE,
        related_name='status_history'
    )
    status = models.CharField(max_length=50)
    note = models.TextField(null=True, blank=True)
    changed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='clearance_status_changes'
    )
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-changed_at']
        verbose_name = 'Clearance Status History'
        verbose_name_plural = 'Clearance Status Histories'

    def __str__(self):
        return f"Form {self.form_id} → {self.status} at {self.changed_at}"

# ======================================================
# CLEARANCE FORM RESUBMISSION
# ======================================================

class ClearanceFormResubmission(models.Model):
    original_form = models.ForeignKey(ClearanceForm, on_delete=models.CASCADE, related_name='resubmissions')
    resubmitted_form = models.ForeignKey(ClearanceForm, on_delete=models.CASCADE, related_name='resubmitted_from')
    reason = models.TextField()
    resubmitted_at = models.DateTimeField(auto_now_add=True)
    resubmitted_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    def __str__(self):
        return f"Resubmission: {self.original_form.id} -> {self.resubmitted_form.id}"

# ======================================================
# NOTIFICATION SYSTEM
# ======================================================

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('info', 'Info'),
        ('success', 'Success'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('payment_required', 'Payment Required'),
        ('system', 'System'),
        ('chat', 'Chat'), 
    ]

    notification_type = models.CharField(  # Add this field
        max_length=30,
        choices=NOTIFICATION_TYPES,
        default='info'
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    clearance_form = models.ForeignKey(
        'ClearanceForm',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    title = models.CharField(max_length=200, blank=True, null=True)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title if self.title else f"Notification for {self.user.username}"

# ======================================================
# CHAT SYSTEM
# ======================================================

class ChatRoom(models.Model):
    ROOM_TYPES = [
        ('student_department_head', 'Student - Department Head'),
        ('student_librarian', 'Student - Librarian'),
        ('student_cafeteria', 'Student - Cafeteria'),
        ('student_dormitory', 'Student - Dormitory'),
        ('student_registrar', 'Student - Registrar'),
    ]
    
    name = models.CharField(max_length=255)
    room_type = models.CharField(max_length=50, choices=ROOM_TYPES)
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='student_chats', null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    specific_staff = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='staff_chats')
    participants = models.ManyToManyField(User, related_name='chat_rooms')
    is_active = models.BooleanField(default=True)
    last_message_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.room_type})"

    def get_other_participant(self, user):
        return self.participants.exclude(id=user.id).first()


class Message(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField()
    file = models.FileField(upload_to='chat_files/', null=True, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Message from {self.sender.username} in {self.room.name}"

    def mark_as_read(self):
        self.is_read = True
        self.save()

        
        # In your models.py, add these models
# In your PaymentMethod model in models.py
class PaymentMethod(models.Model):
    """University payment methods - Customizable by admins"""
    # Remove the fixed METHOD_CHOICES and make name a free text field
    name = models.CharField(max_length=100, verbose_name="Payment Method Name")
    account_number = models.CharField(max_length=50, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    account_name = models.CharField(max_length=200)
    instructions = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Payment Method"
        verbose_name_plural = "Payment Methods"
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} - {self.account_name}"


class StudentPayment(models.Model):
    """Student payment records"""
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending Verification'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    student = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='payments',
        limit_choices_to={'role': 'student'}
    )
    payment_method = models.ForeignKey(
        PaymentMethod, 
        on_delete=models.SET_NULL, 
        null=True
    )
    clearance_form = models.ForeignKey(
        ClearanceForm,
        on_delete=models.CASCADE,
        related_name='payments',
        null=True,
        blank=True,
        help_text="Linked clearance form requiring this payment"
    )
    department_type = models.CharField(
        max_length=50,
        choices=[
            ('library', 'Library'),
            ('cafeteria', 'Cafeteria'),
            ('dormitory', 'Dormitory'),
            ('other', 'Other'),
        ]
    )
    
    # Payment details
    transaction_id = models.CharField(max_length=100, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    receipt_file = models.FileField(upload_to='receipts/')
    receipt_thumbnail = models.ImageField(upload_to='receipts/thumbnails/', null=True, blank=True)



    def generate_thumbnail(self):
        if not self.receipt_file:
            return

        if self.receipt_file.name.lower().endswith(('.jpg', '.jpeg', '.png')):
            try:
                img = Image.open(self.receipt_file)
                img.thumbnail((200, 200))
                thumb_io = BytesIO()
                img.save(thumb_io, format='JPEG')
                thumb_name = f"thumb_{self.receipt_file.name.split('/')[-1]}"
                self.receipt_thumbnail.save(thumb_name, ContentFile(thumb_io.getvalue()), save=False)
            except Exception as e:
                print("Thumbnail generation failed:", e)
    # Verification details
    status = models.CharField(
        max_length=20,
        choices=PAYMENT_STATUS_CHOICES,
        default='pending'
    )
    verified_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='verified_payments'
    )
    verified_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True, null=True)
    
    # Student submission details
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    account_last_digits = models.CharField(max_length=4, blank=True, null=True)
    note = models.TextField(blank=True, null=True, help_text="Payment purpose/reference")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    payment_date = models.DateField()
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Student Payment"
        verbose_name_plural = "Student Payments"
    
    def __str__(self):
        return f"{self.student.username} - {self.amount} - {self.status}"
    
    def save(self, *args, **kwargs):
        # Generate thumbnail for image receipts
        if self.receipt_file and not self.receipt_thumbnail:
            if self.receipt_file.name.lower().endswith(('.jpg', '.jpeg', '.png')):
                self.generate_thumbnail()
        super().save(*args, **kwargs)
    
def generate_thumbnail(self):
    """Generate thumbnail for receipt image"""
    try:
        if not self.receipt_file:
            return
            
        # Open the uploaded file
        img = Image.open(self.receipt_file.file)
        img.thumbnail((200, 200))
        
        # Create thumbnail in memory
        thumb_io = io.BytesIO()
        
        # Determine format
        if img.format == 'PNG':
            img.save(thumb_io, format='PNG')
            extension = 'png'
        else:
            img = img.convert('RGB')
            img.save(thumb_io, format='JPEG', quality=85)
            extension = 'jpg'
        
        # Generate filename
        thumb_name = f"thumb_{self.id}_{int(time.time())}.{extension}"
        
        # Save the thumbnail
        from django.core.files.base import ContentFile
        self.receipt_thumbnail.save(
            thumb_name,
            ContentFile(thumb_io.getvalue()),
            save=False
        )
    except Exception as e:
        print(f"Error generating thumbnail: {e}")


def auto_update_clearance_form(self):
        """Automatically update linked clearance form after verification"""
        try:
            if not self.clearance_form or self.status != 'verified':
                return False
                
            # Map payment department to clearance form status
            status_map = {
                'library': {
                    'requires_status': 'requires_library_payment',
                    'approved_status': 'approved_library',
                    'note_field': 'library_note'
                },
                'cafeteria': {
                    'requires_status': 'requires_cafeteria_payment',
                    'approved_status': 'approved_cafeteria',
                    'note_field': 'cafeteria_note'
                },
                'dormitory': {
                    'requires_status': 'requires_dormitory_payment',
                    'approved_status': 'approved_dormitory',
                    'note_field': 'dormitory_note'
                }
            }
            
            dept_info = status_map.get(self.department_type)
            if not dept_info:
                return False
            
            form = self.clearance_form
            
            # Check if form requires this payment
            if form.status == dept_info['requires_status']:
                # Update form status
                form.status = dept_info['approved_status']
                setattr(form, dept_info['note_field'], 
                       f"Payment verified. Transaction: {self.transaction_id}. Amount: {self.amount}")
                form.updated_at = timezone.now()
                form.save()
                
                # Create notification for student
                Notification.objects.create(
                    user=self.student,
                    message=f"✅ Your payment for {self.department_type} has been verified. Form #{form.id} is now approved.",
                    notification_type="success",
                    clearance_form=form
                )
                
                # Send notification to next department
                self.send_next_department_notification(form)
                
                return True
                
        except Exception as e:
            print(f"Error auto-updating clearance form: {e}")
            return False
    
def send_next_department_notification(self, form):
        """Send notification to next department after payment verification"""
        try:
            next_dept_map = {
                'library': {'role': 'cafeteria', 'name': 'Cafeteria'},
                'cafeteria': {'role': 'dormitory', 'name': 'Dormitory'},
                'dormitory': {'role': 'registrar', 'name': 'Registrar'}
            }
            
            next_dept = next_dept_map.get(self.department_type)
            if next_dept:
                staff_users = User.objects.filter(
                    role=next_dept['role'], 
                    is_active=True
                )
                for staff in staff_users:
                    Notification.objects.create(
                        user=staff,
                        message=f"📋 New clearance form #{form.id} from {self.student.username} ready for {next_dept['name']} check",
                        notification_type="info",
                        clearance_form=form
                    )
        except Exception as e:
            print(f"Error sending next department notification: {e}")


class PaymentVerificationLog(models.Model):
    """Log of payment verification actions"""
    payment = models.ForeignKey(StudentPayment, on_delete=models.CASCADE)
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=20, choices=[('verify', 'Verify'), ('reject', 'Reject')])
    note = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.payment.transaction_id} - {self.action}"
    
    
    
    

# In your models.py, add after PaymentVerificationLog model

class CSVStudentUpload(models.Model):
    """Model to track CSV uploads for authorized students"""
    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='csv_uploads'
    )
    file = models.FileField(upload_to='csv_students/')
    filename = models.CharField(max_length=255)
    total_records = models.IntegerField(default=0)
    successful_records = models.IntegerField(default=0)
    failed_records = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "CSV Student Upload"
        verbose_name_plural = "CSV Student Uploads"
    
    def __str__(self):
        return f"{self.filename} - {self.created_at.strftime('%Y-%m-%d')}"


class AuthorizedStudent(models.Model):
    """Model to store authorized students from CSV - Only requires 3 fields"""
    csv_upload = models.ForeignKey(
        CSVStudentUpload,
        on_delete=models.CASCADE,
        related_name='students',
        null=True,
        blank=True
    )
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    id_number = models.CharField(max_length=50, unique=True)
    # Remove email, college, and department from CSV requirement
    email = models.EmailField(blank=True, null=True)  # Optional
    college = models.ForeignKey(
        College,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    department = models.ForeignKey(
        Department,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    is_active = models.BooleanField(default=True)
    is_registered = models.BooleanField(default=False)
    registered_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='authorized_student'
    )
    registration_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['last_name', 'first_name']
        verbose_name = "Authorized Student"
        verbose_name_plural = "Authorized Students"
        unique_together = ['id_number']  # Only id_number needs to be unique
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.id_number}"
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"