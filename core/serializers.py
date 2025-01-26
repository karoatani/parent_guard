from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.validators import UniqueValidator
from django.core.validators import EmailValidator
from .utils import generate_username
from .models import Account, ChildProfile, ParentProfile, AllowList, BlockList, Schedule, ActivityLog

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data["access"] = str(refresh.access_token)
        data["email"] = self.user.email
        data["role"] = self.user.role
        data["parent_id"] = self.user.parent.id
        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        

        # Customize the payload here, add the user's email
        token["email"] = user.email
        token["first_name"] = user.first_name
        token["last_name"] = user.last_name
        token["role"] = user.role
        token["parent_id"] = user.parent.id
        
        return token


class WebsiteDataSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    website_url = serializers.CharField(max_length=1000)

class DashboardChildSerializer(serializers.ModelSerializer):
    allow_list = WebsiteDataSerializer(many=True, required=False)
    block_list = WebsiteDataSerializer(many=True, required=False)

    class Meta:
        model = ChildProfile
        fields = (
            'id',
            'parent', 
            'name', 
            'age', 
            'device_id', 
            'daily_limit',
            'is_allowed_list',
            'allow_list',
            'block_list'
        )

    def create(self, validated_data):
        allow_list_data = validated_data.pop('allow_list', [])
        block_list_data = validated_data.pop('block_list', [])

        # Create the child profile
        child_profile = ChildProfile.objects.create(**validated_data)

        # Create and add allow list entries
        for website in allow_list_data:
            allow_list_entry = AllowList.objects.create(**website)
            child_profile.allow_list.add(allow_list_entry)

        # Create and add block list entries
        for website in block_list_data:
            block_list_entry = BlockList.objects.create(**website)
            child_profile.block_list.add(block_list_entry)

        return child_profile

    def update(self, instance, validated_data):
        # Handle allow list updates
        if 'allow_list' in validated_data:
            allow_list_data = validated_data.pop('allow_list')
            # Clear existing allow list
            instance.allow_list.clear()
            # Add new allow list entries
            for website in allow_list_data:
                allow_list_entry, _ = AllowList.objects.get_or_create(**website)
                instance.allow_list.add(allow_list_entry)

        # Handle block list updates
        if 'block_list' in validated_data:
            block_list_data = validated_data.pop('block_list')
            # Clear existing block list
            instance.block_list.clear()
            # Add new block list entries
            for website in block_list_data:
                block_list_entry, _ = BlockList.objects.get_or_create(**website)
                instance.block_list.add(block_list_entry)

        # Update remaining fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        return instance

class CustomRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ("id", "email", "password", 'role')

        extra_kwargs = {
            "email": {
                "validators": [
                    EmailValidator,
                    UniqueValidator(
                        queryset=Account.objects.all(),
                        message="This email already exist, use a unique email address",
                    ),
                ]
            }
        }
        
    def create(self, validated_data):
        username = generate_username()
        password = validated_data.pop('password')
        user = Account.objects.create(
            username=username,
            **validated_data,
            is_active=True,
        )

        user.set_password(password)
        user.save()
        
        return user
    
class DashboardChildListSerializer(serializers.ModelSerializer):
    total_blocked_websites = serializers.IntegerField(read_only=True)
    risk_level = serializers.CharField(read_only=True)
    allow_list = WebsiteDataSerializer(many=True, required=False)
    block_list = WebsiteDataSerializer(many=True, required=False)
    
    class Meta:
        model = ChildProfile
        fields = [
            'id',
            'daily_limit',
            'device_id',
            'age',
            'name',
            'parent',
            'last_updated',
            'date_created',
            'profile_image',
            'risk_level',
            'total_blocked_websites',
            'allow_list',
            'block_list',
            'is_allowed_list'
        ]
        
        
        
        
        
class DashboardParentSettingsAllowList(serializers.ModelSerializer):
    class Meta:
        model = AllowList
        fields = ["name", "website_url"]
        
        
        

class DashboardParentSettingsBlockList(serializers.ModelSerializer):
    class Meta:
        model = BlockList
        fields = ["name", "website_url"]
        
        


class DashboardParentSettingsSchedule(serializers.ModelSerializer):
    name = serializers.CharField(max_length=255)
    duration_start = serializers.TimeField()
    duration_end = serializers.TimeField()

    class Meta:
        model = Schedule
        fields = ["id", "name", "duration_start", "duration_end"]

    def validate(self, data):
        """
        Check that duration_end is after duration_start
        """
        if data['duration_start'] >= data['duration_end']:
            raise serializers.ValidationError({
                "duration": "End time must be after start time"
            })
        return data
        
        

class DashboardParentSettingsUser(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    class Meta:
        model = Account
        fields = ["first_name", "last_name", "email"]
        
class DashboardParentSettingsParent(serializers.ModelSerializer):
    user = DashboardParentSettingsUser(required=False)
    id = serializers.IntegerField()
    
    class Meta:
        model = ParentProfile
        fields = ["id", "user", "is_get_report", "is_allowed_list", "default_daily_limit"]
        


class DashboardParentSettingsChild(serializers.ModelSerializer):
    id = serializers.IntegerField()
    
    class Meta:
        model = ChildProfile
        fields = ['id', 'daily_limit']
              
class DashboardParentSettingsUpdateSerializer(serializers.Serializer):
    parent = DashboardParentSettingsParent()
    child = DashboardParentSettingsChild()
    
class DashboardParentSettingsWebsiteDataSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    website_url = serializers.CharField(max_length=1000)

class DashboardParentSettingsAllowBlockListRequestSerializer(serializers.Serializer):
    profile_type = serializers.ChoiceField(choices=['parent', 'child'])
    profile_id = serializers.IntegerField()
    website = DashboardParentSettingsWebsiteDataSerializer()

class DashboardParentSettingsAllowBlockListDeleteSerializer(serializers.Serializer):
    profile_type = serializers.ChoiceField(choices=['parent', 'child'])
    profile_id = serializers.IntegerField()
    website_id = serializers.IntegerField()
    
class DashboardParentSettingsScheduleCreateRequestSerializer(serializers.Serializer):
    profile_id = serializers.IntegerField()
    schedule = DashboardParentSettingsSchedule()
    
class DashboardParentChildrenListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChildProfile
        fields = ['id', 'name', 'age', 'is_global_rules_applied']
        
class DashboardParentSettingsParentOnlySerializer(serializers.Serializer):
    parent = DashboardParentSettingsParent()
        
class DashboardChildGlobalRulesUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChildProfile
        fields = ['id', 'is_global_rules_applied']
        read_only_fields = ['id']
        
class ActivityLogSerializer(serializers.ModelSerializer):
    date_created = serializers.DateTimeField(read_only=False)
    class Meta:
        model = ActivityLog
        fields = ['website_url', 'action', 'reason', 'date_created']

class ChildActivityLogResponseSerializer(serializers.Serializer):
    activity_logs = ActivityLogSerializer(many=True)
    total_blocked_attempts = serializers.IntegerField()

class ChildTodayActivitySerializer(serializers.Serializer):
    child_name = serializers.CharField()
    current_website = serializers.CharField(allow_null=True)
    time_spent = serializers.DurationField()
    blocked_attempts = serializers.IntegerField()

class ChildRecentActivitySerializer(serializers.Serializer):
    child_name = serializers.CharField()
    activities = ActivityLogSerializer(many=True)

class DashboardParentChildrenRecentActivitySerializer(serializers.Serializer):
    children_activities = ChildRecentActivitySerializer(many=True)
    total_activities = serializers.IntegerField()

class UserExtensionChildListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChildProfile
        fields = ['id', 'name']
        
class UserExtensionChildTodayStatsSerializer(serializers.Serializer):
    sites_visited = serializers.IntegerField()
    total_time_spent = serializers.CharField()  # Changed to CharField to handle time string
        
class UserExtensionRecentActivitySerializer(serializers.Serializer):
    website_url = serializers.CharField()
    timestamp = serializers.DateTimeField()

class UserExtensionChildRecentActivityResponseSerializer(serializers.Serializer):
    activities = UserExtensionRecentActivitySerializer(many=True)

class UserExtensionChildDeviceInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChildProfile
        fields = ['id', 'name']
        
class UserExtensionChildScreenTimeSerializer(serializers.Serializer):
    total_time_spent = serializers.CharField()  # Format: HH:MM:SS
    daily_limit = serializers.IntegerField()  # In hours
        
class ScheduleDataSerializer(serializers.Serializer):
    name = serializers.CharField()
    start_time = serializers.CharField()
    end_time = serializers.CharField()

class UserExtensionChildCurrentRestrictionsSerializer(serializers.Serializer):
    recent_schedules = ScheduleDataSerializer(many=True)
        
class ParentEmailSerializer(serializers.Serializer):
    parent_email = serializers.EmailField()
        