from rest_framework import permissions


class IsParent(permissions.BasePermission):
   
    
    def has_permission(self, request, view):
        return request.user.role == 'parent'