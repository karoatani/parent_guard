from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.conf import settings
from django.db.models.signals import post_save

# Create your models here.

ACTION_CHOICES = [
    ('block', 'Block'),
    ('redirect', 'Redirect'),
    ('allow', 'Allow'),
    ('upgrade_scheme', 'upgradeScheme'),
    ('modify_headers', 'modifyHeaders'),
    ('allow_allRequests', 'allowAllRequests')
]
RESOURCE_TYPES = [
    ('main_frame', 'main_frame'),
    ('sub_frame', 'sub_frame'),
    ('stylesheet', 'stylesheet'),
    ('script', 'script'),
    ('image', 'image'),
    ('font', 'font'),
    ('object', 'object'),
    ('xmlhttprequest', 'xmlhttprequest'),
    ('ping', 'ping'),
    ('csp_report', 'csp_report'),
    ('media', 'media'),
    ('websocket', 'websocket'),
    ('webtransport', 'webtransport'),
    ('webbundle', 'webbundle'),
    ('other', 'other'),
]
class Account(AbstractUser):
    ROLE_CHOICES = [('parent', 'Parent'), ('child', 'Child')]
    email = models.EmailField(verbose_name='email', max_length=100, unique=True)
    activate_account_code = models.CharField(max_length=40, blank=True, null=True)
    forgot_password_code = models.CharField(max_length=40, blank=True, null=True)
    role = models.CharField(max_length=255, choices=ROLE_CHOICES)
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['username']
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    

def get_profile_image_filepath(self, filename):
    return 'profile_images/' + str(self.user.username) + "_" + "_" + str(self.pk) + '/profile_image.png'

def get_default_profile_image():
    return "defaultProfileImage/default.jpg"
class ParentProfile(models.Model):
    user = models.OneToOneField('Account', on_delete=models.CASCADE, related_name='parent')
    is_get_report = models.BooleanField(default=True)
    is_allowed_list = models.BooleanField(default=False)
    default_daily_limit = models.PositiveIntegerField(validators=[MinValueValidator(0)], default=0)
    
    allow_list = models.ManyToManyField('AllowList')
    block_list = models.ManyToManyField('BlockList')
    
    
    profile_image = models.ImageField(max_length=255, upload_to=get_profile_image_filepath, 
                                        null=True, blank=True, default=get_default_profile_image)


def parent_profile_receiver(sender, instance, created, *args, **kwargs):
    if created:
        if instance.role == 'parent':
            ParentProfile.objects.create(user=instance)

post_save.connect(parent_profile_receiver, sender=settings.AUTH_USER_MODEL)


class ChildProfile(models.Model):
    parent = models.ForeignKey('ParentProfile', on_delete=models.CASCADE, related_name='child_profile')
    name = models.CharField(max_length=255)
    age = models.PositiveIntegerField(validators=[MinValueValidator(3), MaxValueValidator(27)])
    device_id = models.CharField(max_length=400, unique=True)
    profile_image = models.ImageField(max_length=255, upload_to=get_profile_image_filepath, 
                                        null=True, blank=True, default=get_default_profile_image)
    
    is_global_rules_applied = models.BooleanField(default=True)
    
    schedule = models.ManyToManyField('Schedule', related_name='child_profile', null=True, blank=True)
    
    is_allowed_list = models.BooleanField(default=False)
    
    allow_list = models.ManyToManyField('AllowList', blank=True)
    block_list = models.ManyToManyField('BlockList', blank=True)
    daily_limit = models.PositiveIntegerField(validators=[MinValueValidator(0)], default=0)
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    



class BrowsingHistory(models.Model):
    child = models.ForeignKey('ChildProfile', on_delete=models.CASCADE, related_name='browsing_history')
    website_visited = models.URLField()
    duration = models.TimeField()
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    

class BrowsingSession(models.Model):
    user = models.ForeignKey('ChildProfile', on_delete=models.CASCADE, related_name='browsing_session')
    device_id = models.CharField(max_length=400)
    
    expires_at = models.DateTimeField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    

    
class Schedule(models.Model):
    name = models.CharField(max_length=255)
    duration_start = models.DateTimeField()
    duration_end = models.DateTimeField() 
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    
    
class AllowList(models.Model):
    name = models.CharField(max_length=255)
    website_url = models.CharField(max_length=1000)
    
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    

class BlockList(models.Model):
    name = models.CharField(max_length=255)
    website_url = models.CharField(max_length=1000)
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    
class ActivityLog(models.Model):
    ACTION_CHOICES = [
        ('allowed', 'Allowed'),
        ('blocked', 'Blocked'),
    ]
    
    child = models.ForeignKey('ChildProfile', on_delete=models.CASCADE, related_name='child_activity_log')
    website_url = models.CharField(max_length=1000)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    reason = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
