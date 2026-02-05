# api/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from django.views.generic import TemplateView
router = DefaultRouter()
router.register(r'system-controls', views.SystemControlViewSet, basename='system-control')
router.register(r'chat-rooms', views.ChatRoomViewSet, basename='chatroom')
router.register(r'messages', views.MessageViewSet, basename='message')

urlpatterns = [
    # ==================== AUTHENTICATION ====================
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('check-student-match/', views.check_student_match, name='check_student_match'),
    path('test-authorized-students/', views.test_authorized_students, name='test-authorized-students'),
    
    # Password Reset URLs
    path('send-reset-otp/', views.send_reset_otp, name='send_reset_otp'),
    path('verify-reset-otp/', views.verify_reset_otp, name='verify_reset_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('change-password/', views.change_password, name='change_password'),
    
    # System Status
    path('system/status/', views.system_status, name='system-status'),
    path('system/check-access/', views.check_module_access, name='check-module-access'),
    
    # ==================== CSV TEMPLATE DOWNLOAD ====================
    path('admin/download-csv-template/', views.DownloadCSVTemplateView.as_view(), name='download-csv-template'),
    path('api/system/status/', views.SystemControlViewSet.as_view({'get': 'status'}), name='system-status'),
    path('api/system/check-access/', views.SystemControlViewSet.as_view({'get': 'check_module_access'}), name='check-module-access'),
    
    # ==================== CSV UPLOAD & STUDENT MANAGEMENT ====================
    path('admin/csv-upload/', views.CSVUploadView.as_view(), name='csv-upload'),
    path('admin/csv-uploads/', views.CSVUploadListView.as_view(), name='csv-uploads-list'),
    path('admin/csv-uploads/<int:upload_id>/', views.CSVUploadDetailView.as_view(), name='csv-upload-detail'),
    path('admin/authorized-students/', views.AuthorizedStudentListView.as_view(), name='authorized-students'),
    path('admin/authorized-students/<int:student_id>/', views.AuthorizedStudentDetailView.as_view(), name='authorized-student-detail'),
    path('admin/authorized-students/<int:student_id>/toggle/', views.ToggleAuthorizedStudentView.as_view(), name='toggle-authorized-student'),
    
    # Test endpoint
    path('test-password-reset/', views.test_password_reset, name='test_password_reset'),
    
    # ==================== PUBLIC ENDPOINTS ====================
    path('public/colleges/', views.public_colleges_list, name='public-colleges'),
    path('public/departments/', views.public_departments_list, name='public-departments'),
    
    # ==================== COLLEGE & DEPARTMENT ====================
    path('colleges/', views.college_list, name='college-list'),
    path('departments/', views.department_list, name='department-list'),
    
    # Admin CRUD operations
    path('colleges/create/', views.CollegeListCreateView.as_view(), name='college-create'),
    path('colleges/<int:pk>/', views.CollegeDetailView.as_view(), name='college-detail'),
    path('departments/create/', views.DepartmentListCreateView.as_view(), name='department-create'),
    path('departments/<int:pk>/', views.DepartmentDetailView.as_view(), name='department-detail'),
    
    # ==================== CLEARANCE FORMS ====================
    # Student endpoints
    path('forms/submit/', views.submit_form, name='submit-form'),
    path('forms/student/', views.StudentClearanceFormsView.as_view(), name='student-forms'),
    path('forms/all/', views.get_all_forms, name='all-forms'),  # For registrar
    
    # Admin endpoints
    path('forms/<int:pk>/update/', views.patch_form, name='patch-form'),
    path('admin/form-requests/', views.ClearanceFormRequestsListView.as_view(), name='form-requests'),
    path('admin/form-requests/<int:pk>/', views.update_form_request, name='update-form-request'),
    
    # Form management endpoints
    path('forms/<int:form_id>/', views.get_form_with_faults, name='form_details'),
    path('forms/<int:original_form_id>/resubmit/', views.resubmit_form, name='resubmit_form'),
    path('forms/<int:form_id>/delete/', views.delete_form, name='delete_form'),
    path('forms/<int:form_id>/tracking/', views.get_form_progress, name='form_tracking'),
    
    # ==================== DEPARTMENT HEAD ====================
    path('department-head/forms/', views.department_head_forms, name='dept-head-forms'),
    path('department-head/action/<int:pk>/', views.department_head_action, name='dept-head-action'),
    
    # ==================== LIBRARIAN ====================
    path('librarian/forms/', views.librarian_forms, name='librarian-forms'),
    path('librarian/action/<int:pk>/', views.librarian_action, name='librarian-action'),
    path('librarian/student/<str:student_id>/books/', views.check_book_status_api, name='check-book-status'),
    path('check-book-status/<str:student_id>/', views.check_book_status_api, name='check-book-status-alternate'),
    
    # ==================== CAFETERIA ====================
    path('cafeteria/forms/', views.cafeteria_forms, name='cafeteria-forms'),
    path('cafeteria/action/<int:pk>/', views.cafeteria_action, name='cafeteria-action'),
    path('check-meal-dues/<str:student_id>/', views.check_meal_dues_api, name='check-meal-dues'),
    
    # ==================== DORMITORY ====================
    path('dormitory/forms/', views.dormitory_forms, name='dormitory-forms'),
    path('dormitory/action/<int:pk>/', views.dormitory_action, name='dormitory-action'),
    path('check-dorm-dues/<str:student_id>/', views.check_dorm_dues_api, name='check-dorm-dues'),
    
    # ==================== REGISTRAR ====================
    path('registrar/forms/', views.registrar_forms, name='registrar-forms'),
    path('registrar/action/<int:pk>/', views.registrar_action, name='registrar-action'),
    path('registrar/statistics/', views.registrar_statistics, name='registrar-statistics'),
    path('registrar/certificate/<int:pk>/', views.generate_clearance_certificate, name='generate-certificate'),
    
    # ==================== ADMIN ====================
    path('admin/stats/', views.AdminStatsView.as_view(), name='admin-stats'),
    path('admin/create-user/', views.admin_create_user, name='admin-create-user'),
    path('admin/activities/', views.admin_activities, name='admin-activities'),
    
    # ==================== USERS MANAGEMENT ====================
    path('users/', views.AllUsersListView.as_view(), name='all-users'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),
    
    # ==================== CERTIFICATES ====================
    path('clearance-certificate/<int:form_id>/download/', views.download_clearance_certificate, name='download-clearance-certificate'),
    
    # ==================== NOTIFICATIONS ====================
    path('notifications/stream/', views.notifications_stream, name='notifications-stream'),
    
    # ==================== STUDENT DASHBOARD ====================
    path('student/dashboard/', views.student_dashboard_data, name='student_dashboard'),
    
    # ==================== CHAT SYSTEM ====================
    # Student-specific chat endpoints
    path('student/chat/rooms/', views.student_get_chat_rooms, name='student_chat_rooms'),
    path('student/chat/start/', views.student_start_chat, name='student_start_chat'),
    
    # Department head-specific chat endpoints
    path('department-head/chat/rooms/', views.department_head_get_chat_rooms, name='dept_head_chat_rooms'),
    path('department-head/chat/students/', views.department_head_get_students, name='dept_head_students'),
    path('department-head/chat-rooms/', views.department_head_get_chat_rooms, name='department-head-chat-rooms-legacy'),
    
    # Common chat endpoints
    path('chat/messages/<int:room_id>/', views.get_chat_messages, name='get_chat_messages'),
    path('chat/send/', views.send_message, name='send_chat_message'),
    path('chat/departments/', views.get_departments_for_chat, name='get_chat_departments'),
    path('chat/unread-count/', views.get_unread_message_count, name='unread_message_count'),
    path('chat/mark-read/', views.mark_messages_as_read, name='mark_messages_read'),
    path('chat/start-chat/', views.start_chat_with_department, name='start-chat-alternate'),
    
    # Legacy chat endpoints for compatibility
    path('chat/department-staff/', views.department_staff_list, name='department_staff'),
    path('chat/rooms/', views.get_user_chat_rooms, name='get-user-chat-rooms'),
    path('chat/start/', views.start_chat_with_department, name='start-chat'),
    path('department-staff/', views.DepartmentStaffView.as_view(), name='department_staff_view'),
    
    # ==================== PROFILE MANAGEMENT ====================
    path('profile/', views.get_complete_profile, name='profile'),
    path('profile/basic/', views.get_user_profile, name='profile-basic'),
    path('profile/update/', views.update_user_profile, name='update-profile'),
    path('profile/password/', views.change_user_password_view, name='change-password'),
    path('profile/picture/upload/', views.upload_profile_picture_view, name='upload-profile-picture'),
    path('profile/picture/remove/', views.remove_profile_picture, name='remove-profile-picture'),
    path('profile/settings/', views.get_profile_settings, name='profile-settings'),
    path('profile/settings/update/', views.update_profile_settings, name='update-settings'),
    
    # ==================== PAYMENT SYSTEM ====================
    # Payment URLs
    path('payment/methods/', views.get_payment_methods, name='payment-methods'),
    path('payment/university-accounts/', views.get_university_accounts, name='university-accounts'),
    path('payment/submit/', views.submit_payment, name='submit-payment'),
    path('payment/student/', views.get_student_payments, name='student-payments'),
    path('payment/<int:payment_id>/', views.get_payment_status, name='payment-detail'),
    path('payment/<int:payment_id>/receipt/', views.view_receipt, name='view-receipt'),
    path('payment/<int:payment_id>/verify/', views.verify_payment, name='verify-payment'),
    path('payment/<int:payment_id>/logs/', views.get_payment_verification_logs, name='payment-logs'),
    
    # Staff verification URLs
    path('payment/pending/', views.get_pending_payments, name='pending-payments'),
    path('payment/verified/', views.get_verified_payments, name='verified-payments'),
    
    # Admin payment URLs
    path('admin/payments/all/', views.admin_get_all_payments, name='all-payments'),
    path('admin/payments/<int:payment_id>/update/', views.admin_update_payment, name='admin-update-payment'),
    
    # Payment management (Admin only)
    path('admin/payment-methods/', views.payment_methods_list, name='payment_methods_list'),
    path('admin/payment-methods/<int:pk>/', views.payment_method_detail, name='payment_method_detail'),
    path('admin/payment-methods/create/', views.create_payment_method, name='create_payment_method'),
    path('admin/payment-methods/<int:method_id>/update/', views.update_payment_method, name='update_payment_method'),
    path('admin/payment-methods/<int:method_id>/delete/', views.delete_payment_method, name='delete_payment_method'),
    path('admin/payment-methods/<int:method_id>/toggle/', views.toggle_payment_method_status, name='toggle_payment_method_status'),
    
    # Payment statistics
    path('payment/statistics/', views.payment_statistics, name='payment-statistics'),
    
    # Form payment status
    path('forms/<int:form_id>/payment-status/', views.get_form_payment_status, name='form_payment_status'),
    
    # Updated clearance form action URLs
    path('forms/<int:pk>/librarian-action/', views.librarian_action, name='librarian_action'),
    path('forms/<int:pk>/cafeteria-action/', views.cafeteria_action, name='cafeteria_action'),
    path('forms/<int:pk>/dormitory-action/', views.dormitory_action, name='dormitory_action'),
    
    # Test endpoints
    path('test-view/', views.test_view, name='test_view'),
    path('login-simple/', views.login_view_simple, name='login-simple'),
    path('debug-auth/', views.debug_auth_view, name='debug-auth'),
    path('admin/payment-methods/all/', views.get_all_payment_methods_admin, name='all-payment-methods'),
    path('admin/payments/all/', views.admin_get_all_payments, name='all-payments'),
    # System control
    path('system-closed/', views.system_closed, name='system_closed'),

    path("system-closed/", TemplateView.as_view(template_name="system_closed.html"), name="system_closed"),

  path('payment/methods/', views.get_payment_methods, name='payment-methods'),
    path('admin/payment-methods/all/', views.get_all_payment_methods_admin, name='all-payment-methods'),
    path('admin/payment-methods/create/', views.create_payment_method, name='create_payment_method'),
    path('admin/payment-methods/<int:method_id>/update/', views.update_payment_method, name='update_payment_method'),
    path('admin/payment-methods/<int:method_id>/delete/', views.delete_payment_method, name='delete_payment_method'),
    path('admin/payment-methods/<int:method_id>/toggle/', views.toggle_payment_method_status, name='toggle_payment_method_status'),
    
    # Include router URLs (for ViewSets)
    path('', include(router.urls)),
]