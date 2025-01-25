from django.contrib import admin
from .models import Account, ChildProfile, ParentProfile, BrowsingSession, BrowsingHistory, AllowList, BlockList, Schedule, ActivityLog




admin.site.register(Account)
admin.site.register(ChildProfile)

admin.site.register(ParentProfile)

admin.site.register(BrowsingSession)

admin.site.register(BrowsingHistory)


admin.site.register(AllowList)


admin.site.register(BlockList)

admin.site.register(Schedule)

admin.site.register(ActivityLog)
