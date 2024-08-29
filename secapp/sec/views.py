import os
import time
import subprocess
from django.http import JsonResponse
from django.shortcuts import render, redirect
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

# File Watcher Start
# def filewatch(request):
#     file_logs = FileLogs.objects.all()  # Get all file logs
    
#     if request.method == 'POST':
#         new_path = request.POST.get('new_path')
#         watch_path = WatchPaths.objects.first()
#         watch_path.path = new_path
#         watch_path.save()
#         return redirect('filewatch')

#     current_path = WatchPaths.objects.first().path
#     return render(request, 'filewatch.html', {'file_logs': file_logs, 'current_path': current_path})

def get_file_logs(request): # Get File logs
    logs = FileLogs.objects.all().values('event_type', 'file_path', 'timestamp')
    logs_list = list(logs)  # important: convert the QuerySet to a list
    return JsonResponse(logs_list, safe=False)

def get_event_logs(request):
    logs = Events.objects.all().values(
        'ID', 'EventID', 'SourceName', 'Level', 'Channel', 'Message', 'PredictedValue', 'TimeGenerated'
    )
    logs_list = list(logs)
    return JsonResponse(logs_list, safe=False)

def get_ip_logs(request):
    iplogs = Iplogs.objects.all().values(
        'ID', 'PID', 'Process', 'Local', 'Remote', 'Protocol', 'StartTime', 'CommunicationProtocol', 'LocalIp', 'LocalPort', 'RemoteIp', 'RemotePort'
    )
    iplogs_list = list(iplogs)
    return JsonResponse(iplogs_list, safe=False)

def news(request):
    news_items = News.objects.all()  # Get all news items
    return render(request, 'news.html', {'news_items': news_items})

def search(request):
    return render(request, 'search.html')

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

#####################################################################################
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

#####################################################################################
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
        process.kill()  # Use kill instead of terminate
        try:
            process.wait(timeout=10)  # Wait for the process to end
            process = None
            return JsonResponse({"status": "Script stopped"})
        except subprocess.TimeoutExpired:
            return JsonResponse({"status": "Script could not be stopped"})
    else:
        return JsonResponse({"status": "Script is already stopped"})

#####################################################################################
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

#####################################################################################
# File Watcher Start
def filewatch(request):
    file_logs = FileLogs.objects.all()  # Get all file logs
    
    if request.method == 'POST':
        new_path = request.POST.get('new_path')
        watch_path = WatchPaths.objects.first()
        watch_path.path = new_path
        watch_path.save()
        return redirect('filewatch')

    current_path = WatchPaths.objects.first().path
    return render(request, 'filewatch.html', {'file_logs': file_logs, 'current_path': current_path})

process = None  # Global process instance

def start_watch(request):
    global process
    if request.method == 'POST':
        if process is None or process.poll() is not None:
            script_path = os.path.join(django_settings.SCRIPTS_DIR, 'FileWatchdog.py')
            process = subprocess.Popen(['python', script_path])
            return JsonResponse({'message': 'Watching started.', 'status': 'Watching started.'})
        else:
            return JsonResponse({'message': 'Watcher is already running.', 'status': 'Watcher is already running.'})

def stop_watch(request):
    global process
    if request.method == 'POST':
        if process is not None and process.poll() is None:
            process.terminate()
            for _ in range(10):  # Check for 10 seconds
                if process.poll() is not None:  # Process has ended
                    process = None
                    return JsonResponse({'message': 'Watching stopped.', 'status': 'Watching stopped.'})
                time.sleep(1)  # Wait 1 second between each check
            return JsonResponse({'message': 'Watcher could not be stopped.', 'status': 'Watcher could not be stopped.'})
        else:
            return JsonResponse({'message': 'No watcher to stop.', 'status': 'No watcher to stop.'})

#####################################################################################
# Port Scanner views
def port_scanner(request):
    return render(request, 'port_scanner.html')

def port_results(request):
    open_ports = request.session.get('open_ports', [])  # Oturumdan 'open_ports' listesini alın
    return render(request, 'port_results.html', {'open_ports': open_ports})

# Port Scanner
import socket
import threading
import re
from django.contrib import messages
from django.shortcuts import render, redirect

def port_scanner(request):
    open_ports = []
    if request.method == 'POST':
        target_ip = request.POST.get('ip_address')
        port_min = int(request.POST.get('port_min'))
        port_max = int(request.POST.get('port_max'))

        messages.info(request, 'Port scanning started.')

        # İş parçacıklarını daha etkili kullanmak için port aralığını böl
        num_threads = 10  # Kullanılacak iş parçacığı sayısı
        ports_per_thread = (port_max - port_min + 1) // num_threads

        threads = []
        for i in range(num_threads):
            start_port = port_min + i * ports_per_thread
            end_port = min(start_port + ports_per_thread, port_max + 1)
            thread = threading.Thread(target=scan_port_range, args=(target_ip, start_port, end_port, open_ports))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if not open_ports:
            messages.info(request, 'No open ports found.')
        else:
            messages.success(request, 'Port scanning completed.')

        request.session['open_ports'] = open_ports
        return redirect('port_results')

    return render(request, 'port_scanner.html')

def scan_port_range(target_ip, start_port, end_port, open_ports):
    lock = threading.Lock() # threadler arası senkronizasyon için kilit ekledik
    for port in range(start_port, end_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)  # Zaman aşımını 3 saniyeye çıkar
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    with lock:
                        open_ports.append((port, "OPEN"))
        except socket.timeout:
            with lock:
                open_ports.append((port, "FILTERED"))
        except Exception as e:
            # Hata mesajlarını logla
            print(f"Port {port} taraması sırasında hata oluştu: {e}") 

#####################################################################################
# Task Contoller
import psutil

def task_controller(request):
    """Görev yöneticisi arayüzünü görüntüler."""
    return render(request, 'task_controller.html')

def get_processes(request):
    """Çalışan işlemlerin bilgilerini alır ve JSON formatında döndürür."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']
            if cmdline: # cmdline bilgisinin var olup olmadığını kontrol et
                cmdline = ' '.join(cmdline) 
            else:
                cmdline = '' # Eğer cmdline bilgisi yoksa, boş string ata

            # Yayımcıyı al
            try:
                username = proc.username()
            except psutil.AccessDenied:
                username = "Access Denied"

            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'cpu_percent': proc.info['cpu_percent'],
                'memory_percent': proc.info['memory_percent'],
                'cmdline': cmdline,
                'username': username  # Yayımcıyı ekle
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return JsonResponse({'processes': processes})

def kill_process(request):
    """Gelen istekteki işlem ID'sine göre işlemi sonlandırır."""
    if request.method == 'POST':
        pid = int(request.POST.get('pid', 0))
        try:
            process = psutil.Process(pid)
            process.kill()
            return JsonResponse({'status': 'success', 'message': f'Process {pid} killed successfully.'})
        except psutil.NoSuchProcess:
            return JsonResponse({'status': 'error', 'message': f'Process {pid} not found.'})
        except psutil.AccessDenied:
            return JsonResponse({'status': 'error', 'message': f'Access denied to kill process {pid}.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'})

#####################################################################################
# ARP Scanner
def arp_scanner(request):
    """ARP tablosunu tarar ve sonuçları JSON olarak döndürür."""
    try:
        arp_table = subprocess.check_output(['arp', '-a']).decode('utf-8').split('\n')
        arp_entries = []
        for entry in arp_table:
            if 'Interface' in entry:
                continue
            parts = entry.split()
            if len(parts) >= 3:
                ip_address = parts[0]
                mac_address = parts[1].replace('-', ':')  # MAC adres formatını düzelt
                arp_entries.append({'ip': ip_address, 'mac': mac_address})
        return JsonResponse({'arp_table': arp_entries})
    except Exception as e:
        return JsonResponse({'error': str(e)})

def arp_monitor(request):
    """ARP izleme arayüzünü görüntüler."""
    return render(request, 'arp_monitor.html')

#####################################################################################
# Firewall Monitor
import subprocess
from django.shortcuts import redirect, get_object_or_404
from .models import FirewallRule
# from .models import Rule

def firewall_monitor(request):
    """Güvenlik duvarı izleme arayüzünü görüntüler."""
    rules = FirewallRule.objects.all()
    return render(request, 'firewall_monitor.html', {'rules': rules})

def get_firewall_logs(request):
    """Güvenlik duvarı günlüklerini alır ve analiz eder."""
    # Örnek: iptables günlüklerini okuyun (sisteminize göre özelleştirin)
    try:
        log_output = subprocess.check_output(['sudo', 'iptables', '-L', '-vn']).decode('utf-8')
        log_lines = log_output.split('\n')

        # Basit şüpheli aktivite tespiti (geliştirilebilir)
        suspicious_events = [line for line in log_lines if 'DROP' in line and 'dport=80' in line]

        return JsonResponse({'logs': log_lines, 'suspicious': suspicious_events})
    except Exception as e:
        return JsonResponse({'error': str(e)})

def add_rule(request):
    """Yeni bir güvenlik duvarı kuralı ekler."""
    if request.method == 'POST':
        form_data = request.POST  
        # Form verilerini doğrulayın ve yeni FirewallRule nesnesi oluşturun
        # ...
        new_rule = FirewallRule(
            name=form_data['name'],
            description=form_data['description'],
            action=form_data['action'],
            protocol=form_data['protocol'],
            source_ip=form_data['source_ip'],
            destination_ip=form_data['destination_ip'],
            source_port=form_data['source_port'],
            destination_port=form_data['destination_port'],
            # ... diğer alanlar
        )
        new_rule.save()
        
        # Yeni kuralı sistemin güvenlik duvarına uygulayın (iptables, ufw vb.)
        # ... (örneğin, subprocess.run() ile komut çalıştırın)

        return redirect('firewall_monitor')
    return render(request, 'add_rule.html')

def edit_rule(request, rule_id):
    """Mevcut bir güvenlik duvarı kuralını düzenler."""
    rule = get_object_or_404(FirewallRule, pk=rule_id)
    if request.method == 'POST':
        rule.name = request.POST['name']
        rule.description = request.POST['description']
        rule.action = request.POST['action']
        rule.protocol = request.POST['protocol']
        rule.source_ip = request.POST['source_ip']
        rule.destination_ip = request.POST['destination_ip']
        rule.source_port = request.POST['source_port']
        rule.destination_port = request.POST['destination_port']
        rule.save()
        
        # Güncellenmiş kuralı güvenlik duvarına uygulayın
        # ...

        return redirect('firewall_monitor')
    return render(request, 'edit_rule.html', {'rule': rule})

def delete_rule(request, rule_id):
    """Bir güvenlik duvarı kuralını siler."""
    rule = get_object_or_404(FirewallRule, pk=rule_id)
    rule.delete()
    
    # Kuralı güvenlik duvarından kaldırın
    # ...

    return redirect('firewall_monitor')