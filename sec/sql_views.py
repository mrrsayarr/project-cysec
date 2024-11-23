# sql_views.py
import subprocess
import os
import time
from django.db import connection
from django.http import HttpResponseRedirect, JsonResponse
from sec.models import *
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt

# ONLY  Iplogs table is used in this script
def run_sql(request):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM IpLogs')
    return HttpResponseRedirect('/iplogs/')  # Redirect to the IPLogs page after deleting all records

# ONLY Events table is used in this script

# Clear Error_Logs
def clear_error_logs(request):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM error_logs')
    return HttpResponseRedirect('/settings/')  # Redirect to the settings page after deleting all records

# Clear Event_Logs

# Clear oldest 50 Event_Logs
@csrf_exempt
# def clear_event_logs(request):
#     with connection.cursor() as cursor:
#         cursor.execute('''
#             DELETE FROM events
#             WHERE id IN (
#                 SELECT id FROM events
#                 ORDER BY id ASC
#                 LIMIT 50
#             )
#         ''')
#     return HttpResponseRedirect('/eventlog')  
# Redirect to the eventlog page after deleting the records # Redirect to the eventlog page after deleting the records

# Clear Event_Logs
def clear_event_logs(request):
    with connection.cursor() as cursor:
        cursor.execute('''
            DELETE FROM events
            WHERE predictedValue = 0
        ''')
    return HttpResponseRedirect('/eventlog/')


# Clear Local IPLogs
@csrf_exempt
def clear_local_iplogs(request):
    with connection.cursor() as cursor:
        cursor.execute('''
            DELETE FROM IpLogs
            WHERE RemoteIP = 'localhost' OR RemoteIP = '127.0.0.1'
        ''')
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))  # Redirect to the previous page after deleting the records

# Clear Logs file_logs
def clear_logs(request):
    if request.method == 'POST':
        FileLogs.objects.all().delete()  # Tüm FileLog kayıtlarını sil
        return JsonResponse({'message': 'Logs cleared.'})

