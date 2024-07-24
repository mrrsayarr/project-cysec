import os
import subprocess
from django.http import JsonResponse
from django.shortcuts import render
from sec.models import Events, Iplogs
from django.conf import settings as django_settings  # 'settings' modülünü 'django_settings' olarak import edin
from .sql_views import *

# Create your views here.

def index(request):
    event_logs = Events.objects.all()  # Fetch all records from EventLog table
    return render(request, 'index.html', {'event_logs': event_logs})

def eventlog(request):
    event_logs = Events.objects.all()  # Fetch all records from EventLog table
    return render(request, 'eventlog.html', {'event_logs': event_logs})


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
    count = Iplogs.objects.count()
    return render(request, 'settings.html', {'count': count})

def todo(request):
    return render(request, 'todo.html')

# POST request for IPLogs
process = None

def run_script(request):
    global process
    script_path = os.path.join(django_settings.SCRIPTS_DIR, 'IPController.py')  # 'django_settings' is used instead of 'settings'
    process = subprocess.Popen(['python', script_path])
    return JsonResponse({"status": "Script started"})

import time

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

