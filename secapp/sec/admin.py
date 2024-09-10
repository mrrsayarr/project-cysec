from django.contrib import admin
from .models import Events, Iplogs, WatchPaths, FirewallRule, ErrorLogs, FileLogs, News, Eventdescription

# Register your models here.
# For Only Admin Panel

admin.site.site_header = "Administration Security Dashboard"
admin.site.index_title = "Site administration"

class ReadOnlyAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields]

class IpLogsAdmin(ReadOnlyAdmin):
    search_fields = ["Remote", "Local", "Protocol", "CommunicationProtocol", "LocalIp", "RemoteIp", "LocalPort", "RemotePort", "StartTime", "Process", "PID", "ID"] 
    list_display = ('PID', 'Process', 'LocalIp', 'LocalPort', 'RemoteIp', 'RemotePort', 'Protocol', 'CommunicationProtocol', 'StartTime')
    exclude = ('Local', 'Remote',)

class ErrorLogsAdmin(ReadOnlyAdmin):
    search_fields = ["errormessage", "errortime"]
    list_display = ('errormessage', 'errortime')

class FileLogsAdmin(ReadOnlyAdmin):
    search_fields = ["event_type", "file_path", "timestamp"]
    list_display = ('event_type', 'file_path', 'timestamp')

class NewsAdmin(ReadOnlyAdmin):
    search_fields = ["sourcename", "title"]
    list_display = ('sourcename', 'title')

class EventDescriptionAdmin(ReadOnlyAdmin):
    search_fields = ["EventID", "EventName", "EventDescription"]
    list_display = ('EventID', 'EventName', 'EventDescription')

class EventAdmin(ReadOnlyAdmin):
    search_fields = ["EventID", "PredictedValue", "TimeGenerated", "Message", "SourceName", "Channel"]
    list_display = ('EventID', 'PredictedValue', 'TimeGenerated', 'Message', 'SourceName', 'Channel')

admin.site.register(Iplogs, IpLogsAdmin)
admin.site.register(Events, ReadOnlyAdmin)
admin.site.register(Eventdescription, ReadOnlyAdmin)
admin.site.register(FileLogs, ReadOnlyAdmin)
admin.site.register(News, ReadOnlyAdmin)
admin.site.register(FirewallRule, ReadOnlyAdmin)

# admin.site.register(WatchPaths, ReadOnlyAdmin)
# admin.site.register(ErrorLogs, ReadOnlyAdmin)