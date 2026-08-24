from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
from .models import Settings
# Register your models here




@admin.register(Settings)
class SettingsAdmin(admin.ModelAdmin):
    list_display = ('User', 'theme_mode', 'THRESHOLD', 'Mac_Threshold', 'updated_at')



class NETAdmin(admin.ModelAdmin):
    list_display = ('FNAME','USER','Msg','MsgTime','MsgDate')  # Columns to display
    list_filter = ('FNAME','USER','MsgDate')  # Filters for the list view
    search_fields = ('FNAME','USER')  # Fields to search
    ordering = ('MsgDate',)  # Default ordering
    date_hierarchy = 'MsgDate'  # Adds a date-based drilldown navigation


class FailAdmin(admin.ModelAdmin):
    list_display = ('User','Fail','Date')  # Columns to display
    list_filter = ('User','Fail','Date')  # Filters for the list view
    search_fields = ('User','Fail','Date')  # Fields to search
    ordering = ('Date',)  # Default ordering
    date_hierarchy = 'Date'
    
admin.site.register(NET,NETAdmin)
admin.site.register(PK)
admin.site.register(FailLogin,FailAdmin)