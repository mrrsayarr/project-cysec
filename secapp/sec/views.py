import os
import time
import subprocess
from django.http import JsonResponse
from django.shortcuts import render
from sec.models import Events, Iplogs, FileLogs, ErrorLogs, News, Eventdescription, WatchPaths
from django.conf import settings as django_settings  # 'settings' modülünü 'django_settings' olarak import edin
from .sql_views import *

# Create your views here.

def index(request):
    event_logs = Events.objects.all()  # Fetch all records from EventLog table
    return render(request, 'index.html', {'event_logs': event_logs})

def eventlog(request):
    event_logs = Events.objects.all()  # Fetch all records from EventLog table
    return render(request, 'eventlog.html', {'event_logs': event_logs})

def filewatch(request):
    file_logs = FileLogs.objects.all()  # Get all file logs
    return render(request, 'filewatch.html', {'file_logs': file_logs})

def news(request):
    news_items = News.objects.all()  # Get all news items
    return render(request, 'news.html', {'news_items': news_items})

# IPLogs table is used in this script
import ipaddress

def is_public(ip_with_port):
    ip = ip_with_port.split(":")[0]
    return ipaddress.ip_address(ip).is_global

def iplogs(request):
    iplogs = Iplogs.objects.all()
    iplogs_list = []
    for iplog in iplogs:
        iplog_dict = iplog.__dict__
        iplog_dict['Type'] = "Public" if is_public(iplog.Remote) else "Private"
        iplogs_list.append(iplog_dict)
    return render(request, 'iplogs.html', {'iplogs': iplogs_list})

def settings(request):
    # Count Logs 
    iplogs_count = Iplogs.objects.count()
    errorlogs_count = ErrorLogs.objects.count()
    events_count = Events.objects.count()
    file_logs_count = FileLogs.objects.count()
    news_count = News.objects.count()
    eventdescription_count = Eventdescription.objects.count()
    current_path = WatchPaths.objects.first().path

    # POST for File Watchdogs Start
    if request.method == 'POST':
        new_path = request.POST.get('new_path')
        watch_path = WatchPaths.objects.first()
        watch_path.path = new_path
        watch_path.save()
        return redirect('settings')
    # POST for File Watchdogs End

    return render(request, 'settings.html', {
        'iplogs_count': iplogs_count, 
        'errorlogs_count': errorlogs_count,
        'events_count': events_count,
        'file_logs_count': file_logs_count,
        'news_count': news_count,
        'eventdescription_count': eventdescription_count,
        'current_path': current_path, # POST request
    })

def todo(request):
    return render(request, 'todo.html')

# POST request for IPLogs
process = None # Global variable to store the process

def run_script(request):
    global process
    script_path = os.path.join(django_settings.SCRIPTS_DIR, 'IPController.py')  # 'django_settings' is used instead of 'settings'
    process = subprocess.Popen(['python', script_path])
    return JsonResponse({"status": "Script started"})

def stop_script(request):
    global process
    if process:
        process.terminate()
        # Add a waiting period to check if the process has ended
        for _ in range(10):  # Check for 10 seconds
            if process.poll() is not None:  # Process has ended
                process = None
                return JsonResponse({"status": "Script stopped"})
            time.sleep(1)  # Wait 1 second between each check
        return JsonResponse({"status": "Script could not be stopped"})
    else:
        return JsonResponse({"status": "Script is already stopped"})


# POST request for Eventlog
def run_log_collector(request):
    global process
    script_path = os.path.join(django_settings.SCRIPTS_DIR, 'LogCollector.py')
    process = subprocess.Popen(['python', script_path])
    return JsonResponse({"status": "LogCollector script started"})

from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def stop_log_collector(request):
    global process
    if process:
        process.kill()  # Use kill instead of terminate
        # Add a waiting period to check if the process has ended
        for _ in range(10):  # Check for 10 seconds
            if process.poll() is not None:  # Process has ended
                process = None
                return JsonResponse({"status": "LogCollector script stopped"})
            time.sleep(1)  # Wait 1 second between each check
        return JsonResponse({"status": "LogCollector script could not be stopped"})
    else:
        return JsonResponse({"status": "LogCollector script is already stopped"})
