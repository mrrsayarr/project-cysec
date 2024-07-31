# sql_views.py
from django.db import connection
from django.http import HttpResponseRedirect, JsonResponse
from sec.models import *
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt

# ONLY  Iplogs table is used in this script
def run_sql(request):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM IpLogs')
    return HttpResponseRedirect('/settings')  # Redirect to the IPLogs page after deleting all records

# ONLY Events table is used in this script

# Clear Error_Logs
def clear_error_logs(request):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM error_logs')
    return HttpResponseRedirect('/settings')  # Redirect to the settings page after deleting all records

# Clear Event_Logs
# Clear oldest 50 Event_Logs
@csrf_exempt
def clear_event_logs(request):
    with connection.cursor() as cursor:
        cursor.execute('''
            DELETE FROM events
            WHERE id IN (
                SELECT id FROM events
                ORDER BY id ASC
                LIMIT 50
            )
        ''')
    return HttpResponseRedirect('/eventlog')  # Redirect to the eventlog page after deleting the records

# Clear Local IPLogs
@csrf_exempt
def clear_local_iplogs(request):
    with connection.cursor() as cursor:
        cursor.execute('''
            DELETE FROM IpLogs
            WHERE RemoteIP = 'localhost' OR RemoteIP = '127.0.0.1'
        ''')
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))  # Redirect to the previous page after deleting the records

# Count Logs 
# def count_logs(request):
#     pass
#     iplogs_count = Iplogs.objects.count()
#     errorlogs_count = ErrorLogs.objects.count()
#     events_count = Events.objects.count()
#     file_logs_count = FileLogs.objects.count()
#     news_count = News.objects.count()
#     eventdescription_count = Eventdescription.objects.count()

#     # POST for File Watchdogs Start
#     if request.method == 'POST':
#         new_path = request.POST.get('new_path')
#         watch_path = WatchPaths.objects.first()
#         watch_path.path = new_path
#         watch_path.save()
#         return redirect('count_logs')

#     current_path = WatchPaths.objects.first().path
#     # POST for File Watchdogs End

#     return render(request, 'settings.html', {
#         'iplogs_count': iplogs_count, 
#         'errorlogs_count': errorlogs_count,
#         'events_count': events_count,
#         'file_logs_count': file_logs_count,
#         'news_count': news_count,
#         'eventdescription_count': eventdescription_count,
#         'current_path': current_path, # POST request
#     })

