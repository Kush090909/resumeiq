from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('admin', 'Admin'),
    )
    role = models.CharField(
        max_length=10, 
        choices=ROLE_CHOICES, 
        default='user'
    )
    
    # For account lockout
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # For single session enforcement
    active_session_token = models.CharField(
        max_length=500, 
        blank=True, 
        null=True
    )

    # Fix reverse accessor clash
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions_set',
        blank=True
    )

    def is_locked(self):
        from django.utils import timezone
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        return False

    def __str__(self):
        return self.username