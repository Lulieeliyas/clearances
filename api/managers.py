from django.db import models
from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _


class ActiveManager(models.Manager):
    """
    Custom manager that returns only active objects.
    Use: Student.active.all()
    """
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True)


class Student(models.Model):
    """
    Model representing a student.
    Includes a default manager and a custom manager for active students.
    """
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    # Managers
    objects = models.Manager()      # Default manager (shows all)
    active = ActiveManager()        # Custom manager (shows only active)

    def __str__(self):
        """Return the student's name for easy readability in admin."""
        return self.name
