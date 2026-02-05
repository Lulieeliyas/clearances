from django.contrib.auth.models import Group
from django.db.models.signals import post_migrate
from django.dispatch import receiver

@receiver(post_migrate)
def create_groups(sender, **kwargs):
    departments = ["CSE", "ECE", "Civil"]
    for dept in departments:
        Group.objects.get_or_create(name=f"DepartmentHead_{dept}")
