# sql_views.py
from django.db import connection
from django.http import HttpResponseRedirect, JsonResponse
from sec.models import *
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

# ONLY  Iplogs table is used in this script
def run_sql(request):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM IpLogs')
    return HttpResponseRedirect('/settings')  # Redirect to the IPLogs page after deleting all records

from django.http import HttpResponse

def count_iplogs(request):
    iplogs_count = Iplogs.objects.count()
    return render(request, 'settings.html', {'iplogs_count': iplogs_count})

# ONLY Events table is used in this script

# Clear Error_Logs
def clear_error_logs(request):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM error_logs')
    return HttpResponseRedirect('/settings')  # Redirect to the settings page after deleting all records
    return JsonResponse({"status": "Error logs cleared"})  # Return a JSON response

def count_error_logs(request):
    errorlogs_count = ErrorLogs.objects.count()
    return render(request, 'settings.html', {'errorlogs_count': errorlogs_count})

# Clear Event_Logs
# Clear oldest 10 Event_Logs
@csrf_exempt
def clear_event_logs(request):
    with connection.cursor() as cursor:
        cursor.execute('''
            DELETE FROM events
            WHERE id IN (
                SELECT id FROM events
                ORDER BY id ASC
                LIMIT 100
            )
        ''')
    return HttpResponseRedirect('/eventlog')  # Redirect to the eventlog page after deleting the records