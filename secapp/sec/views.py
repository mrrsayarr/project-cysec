import os
import subprocess
from django.http import JsonResponse
from django.shortcuts import render
from sec.models import Events, Iplogs
from django.conf import settings as django_settings  # 'settings' modülünü 'django_settings' olarak import edin

# Create your views here.

def index(request):
    event_logs = Events.objects.all()  # Fetch all records from EventLog table
    return render(request, 'index.html', {'event_logs': event_logs})

def eventlog(request):
    event_logs = Events.objects.all()  # Fetch all records from EventLog table
    return render(request, 'eventlog.html', {'event_logs': event_logs})

def iplogs(request):
    iplogs = Iplogs.objects.all()
    return render(request, 'iplogs.html', {'iplogs': iplogs})

def settings(request):
    return render(request, 'settings.html')

# POST request for IPLogs
process = None

def run_script(request):
    global process
    script_path = os.path.join(django_settings.SCRIPTS_DIR, 'IPController.py')  # 'settings' yerine 'django_settings' kullanıldı
    process = subprocess.Popen(['python', script_path])
    return JsonResponse({"status": "Script çalıştırıldı"})

import time

def stop_script(request):
    global process
    if process:
        process.terminate()
        # Sürecin sonlandığını kontrol etmek için bir bekleme süresi ekleyin
        for _ in range(10):  # 10 saniye boyunca kontrol et
            if process.poll() is not None:  # Süreç sonlandı
                process = None
                return JsonResponse({"status": "Script durduruldu"})
            time.sleep(1)  # Her kontrol arasında 1 saniye bekle
        return JsonResponse({"status": "Script durdurulamadı"})
    else:
        return JsonResponse({"status": "Script zaten durdurulmuş"})