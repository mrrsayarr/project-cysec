from django.shortcuts import render
from sec.models import Events, Iplogs

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


