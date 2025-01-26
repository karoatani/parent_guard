from django.shortcuts import render
from rest_framework import generics
from .models import Account, ChildProfile, ParentProfile, BrowsingSession, BrowsingHistory, AllowList, BlockList, Schedule, ActivityLog
from .serializers import ( CustomTokenObtainPairSerializer, 
                          CustomRegistrationSerializer,
                          DashboardChildListSerializer,
                          DashboardParentSettingsUpdateSerializer,
                          DashboardParentSettingsAllowBlockListRequestSerializer,
                          DashboardParentSettingsWebsiteDataSerializer,
                          DashboardParentSettingsAllowBlockListDeleteSerializer,
                          DashboardParentSettingsScheduleCreateRequestSerializer,
                          DashboardParentSettingsSchedule,
                          DashboardParentChildrenListSerializer,
                          DashboardParentSettingsParentOnlySerializer,
                          DashboardChildGlobalRulesUpdateSerializer,
                          ActivityLogSerializer,
                          ChildActivityLogResponseSerializer,
                          DashboardChildSerializer,
                          ChildTodayActivitySerializer,
                          DashboardParentChildrenRecentActivitySerializer,
                          UserExtensionChildListSerializer,
                          UserExtensionChildTodayStatsSerializer,
                          UserExtensionRecentActivitySerializer,
                          UserExtensionChildRecentActivityResponseSerializer,
                          UserExtensionChildDeviceInfoSerializer,
                          UserExtensionChildScreenTimeSerializer,
                          UserExtensionChildCurrentRestrictionsSerializer,
                          ParentEmailSerializer
                          )
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status
from rest_framework.views import APIView
from django.http import Http404
import random
from .permissions import IsParent
from django.utils import timezone
from datetime import timedelta
from django.db.models import Sum, Count
from django.db import transaction
from urllib.parse import urlparse
from django.db.models.functions import ExtractHour

import datetime

# Create your views here.


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class CustomRegistrationAPIView(generics.CreateAPIView):
    queryset = Account.objects.all()
    serializer_class = CustomRegistrationSerializer
    permission_classes = (permissions.AllowAny,)
    
    
class DashboardChildRegistrationAPIView(generics.CreateAPIView):
    queryset = ChildProfile.objects.all()
    serializer_class = DashboardChildSerializer
    permission_classes = (permissions.IsAuthenticated, IsParent)
    
    def create(self, request, *args, **kwargs):
        parent_profile = ParentProfile.objects.filter(user=request.user)
        if not (parent_profile):
           return Response({'details': 'You are not allowed to access this resource'}, status=status.HTTP_400_BAD_REQUEST) \
        
        if not (int(request.data.get('parent')) == parent_profile[0].id):
            return Response({'details': 'You are not allowed to access this resource'}, status=status.HTTP_400_BAD_REQUEST)
        return super().create(request, *args, **kwargs)
    
class ChildDeviceIdValidateAPIView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            device_id = self.kwargs['pk']
            child_profile = ChildProfile.objects.filter(device_id=device_id).first()
            
            if not child_profile:
                return Response({
                    "detail": "Device ID not found"
                }, status=status.HTTP_404_NOT_FOUND)
            
            return Response({
                "child_id": child_profile.id,
                "device_id": child_profile.device_id
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                "detail": f"An error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardChildListAPIView(generics.ListAPIView):
    queryset = ChildProfile.objects.all()
    serializer_class = DashboardChildListSerializer
    
    def get_queryset(self):
        parent_profile_id = self.kwargs['pk']
        return super().get_queryset().filter(parent=parent_profile_id)
    
    def get_risk_level(self, blocked_count):
        """Helper method to determine risk level based on blocked attempts"""
        if blocked_count >= 50:
            return "high"
        elif blocked_count >= 20:
            return "medium"
        else:
            return "low"
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Enhance the data with blocked counts and risk levels
        enhanced_data = []
        for child_data in serializer.data:
            child_id = child_data['id']
            
            # Get total blocked websites count from ActivityLog
            blocked_count = ActivityLog.objects.filter(
                child_id=child_id,
                action='blocked'
            ).count()
            
            # Add the additional data
            child_data['total_blocked_websites'] = blocked_count
            child_data['risk_level'] = self.get_risk_level(blocked_count)
            enhanced_data.append(child_data)
        
        return Response(enhanced_data)
    
    





class BrowsingSessionStartAPIView(APIView):
    def post(self, request, *args, **kwargs):
        device_id = request.data.get('device_id')
        website = request.data.get('website')
        
        try:
            child = ChildProfile.objects.get(device_id=device_id)
        except ChildProfile.DoesNotExist:
            return Response({'error': 'Invalid device ID'}, status=status.HTTP_404_NOT_FOUND)
        
        
        # Extract domain name from various URL formats
        parsed_url = urlparse(website)
        domain = parsed_url.netloc or parsed_url.path  # Use path if netloc is empty
        # Remove www. if present and get the first part of the domain
        host_name = domain.replace('www.', '').split('.')[0]
        
        # Check schedules
        current_time = timezone.now()
        current_time_only = current_time.time()  # Get just the time component

        # Get all schedules and check if current time falls within any schedule's time range
        blocked_by_schedule = child.schedule.filter(
            duration_start__time__lte=current_time_only,
            duration_end__time__gte=current_time_only
        ).exists()
        
        
        if blocked_by_schedule:
            # Log blocked access attempt
            ActivityLog.objects.create(
                child=child,
                website_url=host_name,
                action='blocked',
                reason='Schedule restriction'
            )
            return Response({
                'error': 'Access blocked by schedule',
            }, status=status.HTTP_403_FORBIDDEN)

        # Check allow lists and block lists
        is_allowed = True
        block_reason = None
        if child.is_allowed_list:
            child_allow_list = child.allow_list.all()
            if child_allow_list:
                is_allowed = child.allow_list.filter(website_url__contains=host_name).exists()
                if not is_allowed:
                    block_reason = 'Not in child allow list'
            else:
                is_allowed = True
                block_reason = None
        # elif child.is_global_rules_applied:
        #         block_reason = 'Not in child allow list'
        elif child.is_global_rules_applied:
        
            parent = child.parent
            if parent.is_allowed_list:
                is_allowed = parent.allow_list.filter(website_url__contains=host_name).exists()
                if not is_allowed:
                    block_reason = 'Not in parent allow list'
            else:
                is_blocked_by_parent = parent.block_list.filter(website_url__contains=host_name).exists()
                is_blocked_by_child = child.block_list.filter(website_url__contains=host_name).exists()
                print('fuckkkkk')
                is_allowed = not (is_blocked_by_parent or is_blocked_by_child)
                if not is_allowed:
                    block_reason = 'In block list' + (' (parent)' if is_blocked_by_parent else ' (child)')
                    
        else:
            is_blocked_by_child = child.block_list.filter(website_url__contains=host_name).exists()
            is_allowed = not (is_blocked_by_child)
            if not is_allowed:
                    block_reason = 'In block list (child)' 
            

        
        if not is_allowed:
            # Log blocked access attempt
            ActivityLog.objects.create(
                child=child,
                website_url=website,
                action='blocked',
                reason=block_reason
            )
            return Response({
                'error': 'Access to this website is not allowed',
                'reason': block_reason
            }, status=status.HTTP_403_FORBIDDEN)


        # Apply global daily limit if needed
        if child.is_global_rules_applied and child.daily_limit == 0:
            child.daily_limit = child.parent.default_daily_limit
        
        # Get today's start and end time
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)

        # Get or create today's session
        active_session = BrowsingSession.objects.filter(
            user=child,
            device_id=device_id,
            created_at__gte=today_start,
            created_at__lt=today_end
        ).first()
        
        # Calculate remaining time
        today_sessions = BrowsingHistory.objects.filter(
            child=child,
            date_created__gte=today_start
        ).aggregate(total_duration=Sum('duration'))
        
        total_used = today_sessions['total_duration'] or datetime.time(0, 0, 0)
        total_used_seconds = total_used.hour * 3600 + total_used.minute * 60 + total_used.second if isinstance(total_used, datetime.time) else total_used.total_seconds()
        
        daily_limit_seconds = child.daily_limit * 3600
        remaining_seconds = daily_limit_seconds - total_used_seconds

        if remaining_seconds <= 0 and child.daily_limit != 24:
            if active_session:
                active_session.expires_at = timezone.now()
                active_session.save()
            
            ActivityLog.objects.create(
                child=child,
                website_url=website,
                action='blocked',
                reason='Daily limit exceeded'
            )
            return Response({
                'error': 'Daily limit exceeded',
                'remaining_time': 0
            }, status=status.HTTP_403_FORBIDDEN)

        if active_session:
            # Update existing session's expiry
            active_session.expires_at = today_end
            active_session.save()
        else:
            # Create new session for today
            active_session = BrowsingSession.objects.create(
                user=child,
                device_id=device_id,
                expires_at=today_end,
                created_at=timezone.now()
            )

        ActivityLog.objects.create(
            child=child,
            website_url=website,
            action='allowed',
            reason='Session active'
        )

        return Response({
            'session_id': active_session.id,
            'expires_at': active_session.expires_at,
            'remaining_time': remaining_seconds if child.daily_limit != 24 else 'unlimited'
        })

class BrowsingSessionSyncAPIView(APIView):
    def post(self, request, *args, **kwargs):
        device_id = request.data.get('device_id')
        
        try:
            child = ChildProfile.objects.get(device_id=device_id)
        except ChildProfile.DoesNotExist:
            return Response({'error': 'Invalid device ID'}, status=status.HTTP_404_NOT_FOUND)

        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        # Calculate remaining time
        today_sessions = BrowsingHistory.objects.filter(
            child=child,
            date_created__gte=today_start
        ).aggregate(total_duration=Sum('duration'))
        
        total_used = today_sessions['total_duration'] or datetime.time(0, 0, 0)
        total_used_seconds = total_used.hour * 3600 + total_used.minute * 60 + total_used.second if isinstance(total_used, datetime.time) else total_used.total_seconds()
        
        daily_limit_seconds = child.daily_limit * 3600
        remaining_seconds = daily_limit_seconds - total_used_seconds

        # Get or update today's session
        active_session = BrowsingSession.objects.filter(
            user=child,
            device_id=device_id,
            created_at__gte=today_start,
            created_at__lt=today_end
        ).first()

        if active_session:
            if remaining_seconds <= 0 and child.daily_limit != 24:
                active_session.expires_at = timezone.now()
                active_session.save()
                return Response({
                    'error': 'Daily limit exceeded',
                    'remaining_time': 0,
                    'session_id': active_session.id
                }, status=status.HTTP_403_FORBIDDEN)
            
            return Response({
                'session_id': active_session.id,
                'remaining_time': remaining_seconds if child.daily_limit != 24 else 'unlimited'
            })
        
        return Response({'error': 'No active session found'}, status=status.HTTP_404_NOT_FOUND)

class BrowsingHistorySyncAPIView(APIView):
    def post(self, request, *args, **kwargs):
        device_id = request.data.get('device_id')
        website = request.data.get('website')
        duration = request.data.get('duration')  # Expected in seconds
        
        try:
            child = ChildProfile.objects.get(device_id=device_id)
        except ChildProfile.DoesNotExist:
            return Response({'error': 'Invalid device ID'}, status=status.HTTP_404_NOT_FOUND)
        
        
        active_session = BrowsingSession.objects.filter(
            user=child,
            device_id=device_id,
            expires_at__gt=timezone.now()
        ).first()
        
        if not active_session:
            return Response({"details" : "No Active Session"}, status=status.HTTP_400_BAD_REQUEST)
        # Check if daily limit is exceeded
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_sessions = BrowsingHistory.objects.filter(
            child=child,
            date_created__gte=today_start
        ).aggregate(total_duration=Sum('duration'))
        
        total_used = today_sessions['total_duration'] or datetime.time(0, 0, 0)
        total_used_seconds =  total_used.hour * 3600 + total_used.minute * 60 + total_used.second if isinstance(total_used, datetime.time) else total_used.total_seconds()
        
        if total_used_seconds >= child.daily_limit * 3600 and child.daily_limit != 24:
            return Response({
                'error': 'Daily limit exceeded',
                'remaining_time': 0
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Convert duration from seconds to time
        duration_time = datetime.time(
            hour=int(duration) // 3600,
            minute=(int(duration) % 3600) // 60,
            second=int(duration) % 60
        )
        
        BrowsingHistory.objects.create(
            child=child,
            website_visited=website,
            duration=duration_time
        )
        
        
        return Response({'status': 'History synced successfully'})





class DashboardParentSettingsUpdateAPIView(APIView):
    queryset = ParentProfile.objects.all()
    serializer_class = DashboardParentSettingsUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    
    def _update_child_profile(self, child_data):
        """Helper method to update child profile and related data"""
        try:
            child_profile_id = child_data.pop('id')
            child_obj = ChildProfile.objects.get(id=child_profile_id)

            
            # Update remaining child data
            ChildProfile.objects.filter(id=child_profile_id).update(**child_data)
            return True

        except ChildProfile.DoesNotExist:
            return False

    def _update_parent_profile(self, parent_data, request):
        """Helper method to update parent profile and related data"""
        parent_profile = request.user.parent
        if not parent_profile:
            raise ValueError("No parent profile found for user")

        parent_profile_id = parent_data.pop('id')
        if parent_profile_id != parent_profile.id:
            raise PermissionError("Unauthorized access to parent profile")

        # Extract nested data
        user_data = parent_data.pop('user')
        
        
        # Update parent and user data
        with transaction.atomic():
            ParentProfile.objects.filter(id=parent_profile_id).update(**parent_data)
            Account.objects.filter(parent__id=parent_profile_id).update(**user_data)

    @transaction.atomic
    def put(self, request, *args, **kwargs):
        """Handle PUT request to update parent and child settings"""
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            # Update child profile if provided
            if child_data := data.get('child'):
                if not self._update_child_profile(child_data):
                    return Response(
                        {"detail": "Child profile not found"}, 
                        status=status.HTTP_404_NOT_FOUND
                    )

            # Update parent profile
            if parent_data := data.get('parent'):
                try:
                    self._update_parent_profile(parent_data, request)
                except PermissionError:
                    return Response(
                        {"detail": "You do not have permission to access this resource"}, 
                        status=status.HTTP_401_UNAUTHORIZED
                    )
                except ValueError as e:
                    return Response(
                        {"detail": str(e)}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

            return Response({"detail": "Settings updated successfully"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"detail": f"An error occurred: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class DashboardParentSettingsAllowListCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Use the request serializer to validate input
        serializer = DashboardParentSettingsAllowBlockListRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        
        profile_type = validated_data['profile_type']
        profile_id = validated_data['profile_id']
        website_data = validated_data['website']

        try:
            # Create the allow list entry
            allow_list = AllowList.objects.create(
                name=website_data['name'],
                website_url=website_data['website_url']
            )

            # Add to appropriate profile
            if profile_type == 'parent':
                profile = ParentProfile.objects.get(id=profile_id)
            else:
                profile = ChildProfile.objects.get(id=profile_id)
            
            profile.allow_list.add(allow_list)

            # Use the website data serializer for response
            response_serializer = DashboardParentSettingsWebsiteDataSerializer(allow_list)
            return Response({
                'message': 'Website added to allow list successfully',
                'data': response_serializer.data
            }, status=status.HTTP_201_CREATED)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    
class DashboardParentSettingsAllowListDeleteAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, profile_type, profile_id, website_name):
        try:
            # Get the profile based on type
            if profile_type == 'parent':
                profile = ParentProfile.objects.get(id=profile_id)
            else:
                profile = ChildProfile.objects.get(id=profile_id)

            # Find the website by name in the profile's allow list
            website = profile.allow_list.get(name=website_name)
            profile.allow_list.remove(website)
            website.delete()

            return Response({
                'message': 'Website removed from allow list successfully'
            }, status=status.HTTP_200_OK)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except AllowList.DoesNotExist:
            return Response({
                'error': 'Website not found in allow list'
            }, status=status.HTTP_404_NOT_FOUND)


class DashboardParentSettingsAllowListRetrieveAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, profile_type, profile_id):
        try:
            if profile_type == 'parent':
                profile = ParentProfile.objects.get(id=profile_id)
            else:
                profile = ChildProfile.objects.get(id=profile_id)
            
            allow_list = profile.allow_list.all()
            serializer = DashboardParentSettingsWebsiteDataSerializer(allow_list, many=True)
            
            return Response({
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)

class DashboardParentSettingsBlockListCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = DashboardParentSettingsAllowBlockListRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        
        profile_type = validated_data['profile_type']
        profile_id = validated_data['profile_id']
        website_data = validated_data['website']

        try:
            # Create the block list entry
            block_list = BlockList.objects.create(
                name=website_data['name'],
                website_url=website_data['website_url']
            )

            # Add to appropriate profile
            if profile_type == 'parent':
                profile = ParentProfile.objects.get(id=profile_id)
            else:
                profile = ChildProfile.objects.get(id=profile_id)
            
            profile.block_list.add(block_list)

            response_serializer = DashboardParentSettingsWebsiteDataSerializer(block_list)
            return Response({
                'message': 'Website added to block list successfully',
                'data': response_serializer.data
            }, status=status.HTTP_201_CREATED)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class DashboardParentSettingsBlockListDeleteAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, profile_type, profile_id, website_name):
        try:
            # Get the profile based on type
            if profile_type == 'parent':
                profile = ParentProfile.objects.get(id=profile_id)
            else:
                profile = ChildProfile.objects.get(id=profile_id)

            # Find the website by name in the profile's block list
            website = profile.block_list.get(name=website_name)
            profile.block_list.remove(website)
            website.delete()

            return Response({
                'message': 'Website removed from block list successfully'
            }, status=status.HTTP_200_OK)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except BlockList.DoesNotExist:
            return Response({
                'error': 'Website not found in block list'
            }, status=status.HTTP_404_NOT_FOUND)

class DashboardParentSettingsBlockListRetrieveAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, profile_type, profile_id):
        try:
            if profile_type == 'parent':
                profile = ParentProfile.objects.get(id=profile_id)
            else:
                profile = ChildProfile.objects.get(id=profile_id)
            
            block_list = profile.block_list.all()
            serializer = DashboardParentSettingsWebsiteDataSerializer(block_list, many=True)
            
            return Response({
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)

class DashboardParentSettingsScheduleCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Validate request data using serializer
            serializer = DashboardParentSettingsScheduleCreateRequestSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data

            profile_id = validated_data['profile_id']
            schedule_data = validated_data['schedule']

            profile = ChildProfile.objects.get(id=profile_id)
            # Create the schedule
            schedule = Schedule.objects.create(**schedule_data)
            
            # Add to profile's schedule
            profile.schedule.add(schedule)

            response_serializer = DashboardParentSettingsSchedule(schedule)
            return Response({
                'message': 'Schedule created successfully',
                'data': response_serializer.data
            }, status=status.HTTP_201_CREATED)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class DashboardParentSettingsScheduleDeleteAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, profile_id, schedule_id):
        try:
            profile = ChildProfile.objects.get(id=profile_id)

            # Find the schedule by name
            schedule = profile.schedule.get(id=schedule_id, child_profile=profile)
            profile.schedule.remove(schedule)
            schedule.delete()

            return Response({
                'message': 'Schedule removed successfully'
            }, status=status.HTTP_200_OK)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Schedule.DoesNotExist:
            return Response({
                'error': 'Schedule not found'
            }, status=status.HTTP_404_NOT_FOUND)

class DashboardParentSettingsScheduleRetrieveAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, profile_id):
        try:
            profile = ChildProfile.objects.get(id=profile_id)
            
            schedules = profile.schedule.all()
            serializer = DashboardParentSettingsSchedule(schedules, many=True)
            
            return Response({
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        except (ParentProfile.DoesNotExist, ChildProfile.DoesNotExist):
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)

class DashboardParentSettingsScheduleUpdateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, profile_id, schedule_id):
        try:
            # Validate request data
            serializer = DashboardParentSettingsSchedule(data=request.data)
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data

            # Get the child profile and schedule
            profile = ChildProfile.objects.get(id=profile_id)
            schedule = profile.schedule.get(id=schedule_id)
            
            # Update schedule fields
            schedule.name = validated_data.get('name', schedule.name)
            schedule.duration_start = validated_data.get('duration_start', schedule.duration_start)
            schedule.duration_end = validated_data.get('duration_end', schedule.duration_end)
            schedule.save()

            # Return updated schedule data
            response_serializer = DashboardParentSettingsSchedule(schedule)
            return Response({
                'message': 'Schedule updated successfully',
                'data': response_serializer.data
            }, status=status.HTTP_200_OK)

        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Schedule.DoesNotExist:
            return Response({
                'error': 'Schedule not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
            
            
            
class DashboardParentChildrenListAPIView(generics.ListAPIView):
    serializer_class = DashboardParentChildrenListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        parent_id = self.kwargs.get('parent_id')
        return ChildProfile.objects.filter(parent_id=parent_id)

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            if not queryset.exists():
                return Response({
                    'message': 'No children found for this parent',
                    'data': []
                }, status=status.HTTP_200_OK)
            
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'message': 'Children retrieved successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
            

class DashboardParentSettingsRetrieveAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        try:
            parent_profile_id = request.user.parent.id
            parent_profile = ParentProfile.objects.get(id=parent_profile_id)
            if not parent_profile:
                return Response(
                    {"detail": "No parent profile found for user"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Serialize parent data
            response_data = {
                "parent": {
                    "id": parent_profile.id,
                    "user": {
                        "first_name": parent_profile.user.first_name,
                        "last_name": parent_profile.user.last_name,
                        "email": parent_profile.user.email
                    },
                    "is_get_report": parent_profile.is_get_report,
                    "is_allowed_list": parent_profile.is_allowed_list,
                    "default_daily_limit": parent_profile.default_daily_limit
                }
            }
            
            
            serializer = DashboardParentSettingsParentOnlySerializer(data=response_data)
                
            serializer.is_valid(raise_exception=True)
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {"detail": f"An error occurred: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class DashboardParentSettingsUpdateParentOnlyAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def put(self, request, *args, **kwargs):
        try:
            # Validate request data
            serializer = DashboardParentSettingsParentOnlySerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data
            
            # Get parent data
            parent_data = validated_data.get('parent')
            if not parent_data:
                return Response(
                    {"detail": "Parent data is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get parent profile
            # parent_profile = request.user.parent
            parent_profile = ParentProfile.objects.get(id=parent_data['id'])
            
            # Update user data if provided
            user_data = parent_data.get('user')
            if user_data:
                for field, value in user_data.items():
                    setattr(parent_profile.user, field, value)
                parent_profile.user.save()
            
            # Update parent profile fields
            parent_fields = ['is_get_report', 'is_allowed_list', 'default_daily_limit']
            for field in parent_fields:
                if field in parent_data:
                    setattr(parent_profile, field, parent_data[field])
            parent_profile.save()
            
            # Prepare response data
            response_data = {
                "parent": {
                    "id": parent_profile.id,
                    "user": {
                        "first_name": parent_profile.user.first_name,
                        "last_name": parent_profile.user.last_name,
                        "email": parent_profile.user.email
                    },
                    "is_get_report": parent_profile.is_get_report,
                    "is_allowed_list": parent_profile.is_allowed_list,
                    "default_daily_limit": parent_profile.default_daily_limit
                }
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except ParentProfile.DoesNotExist:
            return Response(
                {"detail": "Parent profile not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"detail": f"An error occurred: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            





class DashboardParentSettingsProfilePictureRetrieveAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, parent_id):
        try:
            parent_profile = ParentProfile.objects.get(id=parent_id)
            
            # Check if profile picture exists
            if not parent_profile.profile_image:
                return Response({
                    "detail": "No profile picture found",
                    "profile_picture_url": None
                }, status=status.HTTP_200_OK)
            
            # Return the URL of the profile picture
            return Response({
                "detail": "Profile picture retrieved successfully",
                "profile_picture_url": request.build_absolute_uri(parent_profile.profile_image.url)
            }, status=status.HTTP_200_OK)
            
        except ParentProfile.DoesNotExist:
            return Response({
                "detail": "Parent profile not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "detail": f"An error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardParentSettingsProfilePictureUpdateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def put(self, request, parent_id):
        try:
            parent_profile = ParentProfile.objects.get(id=parent_id)
            
            # Check if an image file was provided in the request
            if 'profile_image' not in request.FILES:
                return Response({
                    "detail": "No image file provided"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Delete old profile picture if it exists
            if parent_profile.profile_image:
                parent_profile.profile_image.delete()
            # Update with new profile picture
            parent_profile.profile_image = request.FILES['profile_image']
            parent_profile.save()
            
            return Response({
                "detail": "Profile picture updated successfully",
                "profile_picture_url": request.build_absolute_uri(parent_profile.profile_image.url)
            }, status=status.HTTP_200_OK)
            
        except ParentProfile.DoesNotExist:
            return Response({
                "detail": "Parent profile not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "detail": f"An error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardChildGlobalRulesUpdateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, child_id):
        try:
            # Get the child profile
            child_profile = ChildProfile.objects.get(id=child_id)
            
            # Validate and update the data
            serializer = DashboardChildGlobalRulesUpdateSerializer(
                child_profile,
                data=request.data,
                partial=True
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            
            return Response({
                'message': 'Global rules setting updated successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class DashboardChildActivityLogAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_date_range(self, filter_type):
        """Helper method to get date range based on filter type"""
        now = timezone.now()
        
        if filter_type == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = now
        elif filter_type == 'last_7_days':
            start_date = now - timedelta(days=7)
            end_date = now
        elif filter_type == 'last_30_days':
            start_date = now - timedelta(days=30)
            end_date = now
        elif filter_type == 'last_3_months':
            start_date = now - timedelta(days=90)
            end_date = now
        elif filter_type == 'last_year':
            start_date = now - timedelta(days=365)
            end_date = now
        else:
            return None, None
            
        return start_date, end_date

    def get(self, request, child_id):
        try:
            # Get the filter type from query parameters
            filter_type = request.query_params.get('filter', 'today')
            
            # Get date range based on filter
            start_date, end_date = self.get_date_range(filter_type)
            if not start_date or not end_date:
                return Response({
                    'error': 'Invalid filter type. Use: today, last_7_days, last_30_days, last_3_months, last_year'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get the child profile
            child_profile = ChildProfile.objects.get(id=child_id)
            
            # Get filtered activity logs for the child
            activity_logs = ActivityLog.objects.filter(
                child=child_profile,
                date_created__gte=start_date,
                date_created__lte=end_date
            ).order_by('-date_created')
            
            # Get total blocked attempts for the filtered period
            total_blocked = activity_logs.filter(action='blocked').count()
            
            response_data = {
                'activity_logs': ActivityLogSerializer(activity_logs, many=True).data,
                'total_blocked_attempts': total_blocked,
                'filter_applied': filter_type,
                'date_range': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                }
            }
            
            serializer = ChildActivityLogResponseSerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardParentChildrenActivityLogAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_date_range(self, filter_type):
        """Helper method to get date range based on filter type"""
        now = timezone.now()
        
        if filter_type == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = now
        elif filter_type == 'last_7_days':
            start_date = now - timedelta(days=7)
            end_date = now
        elif filter_type == 'last_30_days':
            start_date = now - timedelta(days=30)
            end_date = now
        elif filter_type == 'last_3_months':
            start_date = now - timedelta(days=90)
            end_date = now
        elif filter_type == 'last_year':
            start_date = now - timedelta(days=365)
            end_date = now
        else:
            return None, None
            
        return start_date, end_date

    def get(self, request, parent_id):
        try:
            # Get the filter type from query parameters
            filter_type = request.query_params.get('filter', 'today')
            
            # Get date range based on filter
            start_date, end_date = self.get_date_range(filter_type)
            if not start_date or not end_date:
                return Response({
                    'error': 'Invalid filter type. Use: today, last_7_days, last_30_days, last_3_months, last_year'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get all children of the parent
            children = ChildProfile.objects.filter(parent_id=parent_id)
            
            children_logs = []
            total_blocked = 0
            
            for child in children:
                # Get filtered activity logs for each child
                activity_logs = ActivityLog.objects.filter(
                    child=child,
                    date_created__gte=start_date,
                    date_created__lte=end_date
                ).order_by('-date_created')
                
                # Get blocked attempts for this child
                child_blocked = activity_logs.filter(action='blocked').count()
                total_blocked += child_blocked
                
                children_logs.append({
                    'child_id': child.id,
                    'child_name': child.name,
                    'activity_logs': ActivityLogSerializer(activity_logs, many=True).data,
                    'blocked_attempts': child_blocked
                })
            
            response_data = {
                'children_logs': children_logs,
                'total_blocked_attempts': total_blocked,
                
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardChildUpdateAPIView(generics.UpdateAPIView):
    queryset = ChildProfile.objects.all()
    serializer_class = DashboardChildSerializer
    permission_classes = (permissions.IsAuthenticated, IsParent)
    
    def update(self, request, *args, **kwargs):
        # Check if the parent making the request owns this child profile
        parent_profile = ParentProfile.objects.filter(user=request.user).first()
        if not parent_profile:
            return Response(
                {'details': 'You are not allowed to access this resource'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the child profile
        child_profile = self.get_object()
        
        # Verify the child belongs to the requesting parent
        if child_profile.parent.id != parent_profile.id:
            return Response(
                {'details': 'You are not allowed to access this resource'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        return super().update(request, *args, **kwargs)

class DashboardParentChildrenCountAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, parent_id):
        try:
            # Get count of children for the specified parent
            children_count = ChildProfile.objects.filter(parent_id=parent_id).count()
            
            return Response({
                'message': 'Children count retrieved successfully',
                'count': children_count
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardParentTotalBlockedTodayAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, parent_id):
        try:
            # Get today's start time
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Get all children of the parent
            children = ChildProfile.objects.filter(parent_id=parent_id)
            
            # Get total blocked sites today across all children
            total_blocked = ActivityLog.objects.filter(
                child__in=children,
                action='blocked',
                date_created__gte=today_start
            ).values('website_url').distinct().count()
            print(total_blocked)
            
            return Response({
                'message': 'Total blocked sites retrieved successfully',
                'total_blocked_today': total_blocked
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardParentChildrenTodayActivityAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, parent_id):
        try:
            # Get today's start time
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Get all children of the parent
            children = ChildProfile.objects.filter(parent_id=parent_id)
            
            active_children_data = []
            
            for child in children:
                # Get today's activity logs
                today_logs = ActivityLog.objects.filter(
                    child=child,
                    date_created__gte=today_start
                )
                
                # Skip if no activity today
                if not today_logs.exists():
                    continue
                
                # Get most recent allowed website (current website)
                current_activity = today_logs.filter(
                    action='allowed'
                ).order_by('-date_created').first()
                
                if not current_activity:
                    continue
                
                # Get blocked attempts count
                blocked_attempts = today_logs.filter(action='blocked').count()
                # Calculate time since first activity
                first_activity = today_logs.order_by('date_created').first()
                time_spent = timezone.now() - first_activity.date_created
                child_data = {
                    'child_name': child.name,
                    'current_website': current_activity.website_url,
                    'time_spent': time_spent,
                    'blocked_attempts': blocked_attempts
                }
                
                active_children_data.append(child_data)
            
            # Serialize the data
            serializer = ChildTodayActivitySerializer(data=active_children_data, many=True)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'message': 'Today\'s activity retrieved successfully',
                'data': serializer.validated_data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardParentChildrenRecentActivityAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, parent_id):
        try:
            # Get today's start time
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Get all children of the parent
            children = ChildProfile.objects.filter(parent_id=parent_id)
            
            children_activities = []
            total_activities = 0
            
            for child in children:
                # Get today's activity logs for both allowed and blocked activities
                # Limit to latest 5 activities per child
                today_logs = ActivityLog.objects.filter(
                    child=child,
                    date_created__gte=today_start
                ).order_by('-date_created')[:5]  # Added slice for latest 5
                
                if today_logs.exists():
                    # Serialize the activity logs first
                    activity_serializer = ActivityLogSerializer(today_logs, many=True)
                    child_data = {
                        'child_name': child.name,
                        'activities': activity_serializer.data
                    }
                    children_activities.append(child_data)
                    total_activities += today_logs.count()
            
            response_data = {
                'children_activities': children_activities,
                'total_activities': total_activities
            }
            
            # Serialize the data
            serializer = DashboardParentChildrenRecentActivitySerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'message': 'Recent activities retrieved successfully',
                'data': serializer.validated_data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardParentDailyActivityGraphAPIView(APIView):
    def get(self, request, parent_id):
        try:
            # Get today's start time
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Get all children of the parent
            children = ChildProfile.objects.filter(parent_id=parent_id)
            
            # Get hourly activity data
            hourly_data = ActivityLog.objects.filter(
                child__in=children,
                date_created__gte=today_start
            ).annotate(
                hour=ExtractHour('date_created')
            ).values('hour', 'action').annotate(
                count=Count('id')
            ).order_by('hour')
            
            # Format data for the graph
            graph_data = {
                'labels': list(range(24)),  # 24 hours
                'allowed': [0] * 24,
                'blocked': [0] * 24
            }
            
            for entry in hourly_data:
                hour = entry['hour']
                if entry['action'] == 'allowed':
                    graph_data['allowed'][hour] = entry['count']
                else:
                    graph_data['blocked'][hour] = entry['count']
            
            return Response({
                'message': 'Daily activity data retrieved successfully',
                'data': graph_data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardParentTopBlockedSitesAPIView(APIView):
    def get(self, request, parent_id):
        try:
            # Get all children of the parent
            children = ChildProfile.objects.filter(parent_id=parent_id)
            
            # Get today's blocked websites data
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            top_blocked = ActivityLog.objects.filter(
                child__in=children,
                action='blocked',
                date_created__gte=today_start
            ).values('website_url').annotate(
                count=Count('id')
            ).order_by('-count')[:5]  # Get top 5 blocked sites
            
            return Response({
                'message': 'Top blocked sites retrieved successfully',
                'data': list(top_blocked)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserExtensionParentChildrenListAPIView(generics.ListAPIView):
    serializer_class = UserExtensionChildListSerializer
    pagination_class = None
    # permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        parent_id = self.kwargs.get('parent_id')
        return ChildProfile.objects.filter(parent_id=parent_id)
    
    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            if not queryset.exists():
                return Response({
                    'message': 'No children found for this parent',
                    'data': []
                }, status=status.HTTP_200_OK)
            
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'message': 'Children retrieved successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserExtensionChildTodayStatsAPIView(APIView):
    # permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, child_id):
        try:
            # Get today's start time
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Get the child profile
            child = ChildProfile.objects.get(id=child_id)
            
            # Get unique sites visited today
            sites_visited = ActivityLog.objects.filter(
                child=child,
                action='allowed',
                date_created__gte=today_start
            ).values('website_url').distinct().count()
            
            # Calculate total time spent from BrowsingHistory
            browsing_records = BrowsingHistory.objects.filter(
                child=child,
                date_created__gte=today_start
            )
            print(browsing_records)
            
            total_hours = 0
            total_minutes = 0
            total_seconds = 0
            
            for record in browsing_records:
                duration = record.duration
                total_hours += duration.hour
                total_minutes += duration.minute
                total_seconds += duration.second
            
            # Convert excess seconds and minutes
            total_minutes += total_seconds // 60
            total_seconds = total_seconds % 60
            total_hours += total_minutes // 60
            total_minutes = total_minutes % 60
            
            total_time_spent = datetime.time(
                hour=total_hours,
                minute=total_minutes,
                second=total_seconds
            )
            
            # Prepare response data
            response_data = {
                'sites_visited': sites_visited,
                'total_time_spent': total_time_spent.strftime('%H:%M:%S')  # Format as HH:MM:SS
            }
            
            serializer = UserExtensionChildTodayStatsSerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'message': 'Today\'s stats retrieved successfully',
                'data': serializer.validated_data
            }, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserExtensionChildRecentActivityAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_domain_name(self, url):
        """Helper method to extract clean domain name from URL"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path  # Use path if netloc is empty
        # Remove www. if present and get base domain
        clean_domain = domain.replace('www.', '')
        return clean_domain
    
    def get(self, request, child_id):
        try:
            # Get the child profile
            child = ChildProfile.objects.get(id=child_id)
            
            # Get recent activities (last 3)
            recent_activities = ActivityLog.objects.filter(
                child=child,
                action='allowed'  # Only get allowed visits
            ).order_by('-date_created')[:3]
            
            # Format the activities data
            activities_data = []
            for activity in recent_activities:
                clean_url = self.get_domain_name(activity.website_url)
                activities_data.append({
                    'website_url': clean_url,
                    'timestamp': activity.date_created
                })
            
            # Prepare response data
            response_data = {
                'activities': activities_data
            }
            
            serializer = UserExtensionChildRecentActivityResponseSerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'message': 'Recent activities retrieved successfully',
                'data': serializer.validated_data
            }, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserExtensionChildDeviceInfoAPIView(APIView):
    def get(self, request, device_id):
        try:
            # Get child profile using device_id
            child = ChildProfile.objects.get(device_id=device_id)
            
            serializer = UserExtensionChildDeviceInfoSerializer(child)
            
            return Response({
                'message': 'Child info retrieved successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserExtensionChildScreenTimeAPIView(APIView):
    def get(self, request, device_id):
        try:
            # Get today's start time
            today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Get the child profile
            child = ChildProfile.objects.get(device_id=device_id)
            
            # Calculate total time spent from BrowsingHistory
            browsing_records = BrowsingHistory.objects.filter(
                child=child,
                date_created__gte=today_start
            )
            
            # Calculate total time spent
            total_hours = 0
            total_minutes = 0
            total_seconds = 0
            
            for record in browsing_records:
                duration = record.duration
                total_hours += duration.hour
                total_minutes += duration.minute
                total_seconds += duration.second
            
            # Convert excess seconds and minutes
            total_minutes += total_seconds // 60
            total_seconds = total_seconds % 60
            total_hours += total_minutes // 60
            total_minutes = total_minutes % 60
            
            total_time_spent = datetime.time(
                hour=total_hours,
                minute=total_minutes,
                second=total_seconds
            )
            
            # Prepare response data
            response_data = {
                'total_time_spent': total_time_spent.strftime('%H:%M:%S'),
                'daily_limit': child.daily_limit
            }
            
            serializer = UserExtensionChildScreenTimeSerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'message': 'Screen time data retrieved successfully',
                'data': serializer.validated_data
            }, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserExtensionChildCurrentRestrictionsAPIView(APIView):
    def get(self, request, device_id):
        try:
            # Get the child profile using device_id
            child = ChildProfile.objects.get(device_id=device_id)
            
            # Get 3 most recent schedules
            recent_schedules = child.schedule.all().order_by('-date_created')[:3]
            
            # Format schedules data
            schedules_data = []
            for schedule in recent_schedules:
                schedules_data.append({
                    'name': schedule.name,
                    'start_time': schedule.duration_start.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': schedule.duration_end.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            response_data = {
                'recent_schedules': schedules_data
            }
            
            serializer = UserExtensionChildCurrentRestrictionsSerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            return Response({
                'message': 'Recent schedules retrieved successfully',
                'data': serializer.validated_data
            }, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class UserExtensionParentEmailAPIView(APIView):
    def get(self, request, device_id):
        try:
            # Get child profile using device_id
            child = ChildProfile.objects.get(device_id=device_id)
            
            # Get parent email through relationships
            parent_email = child.parent.user.email
            
            serializer = ParentEmailSerializer(data={'parent_email': parent_email})
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'message': 'Parent email retrieved successfully',
                'data': serializer.validated_data
            }, status=status.HTTP_200_OK)
            
        except ChildProfile.DoesNotExist:
            return Response({
                'error': 'Child profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)