# sql_views.py
from django.db import connection
from django.http import HttpResponseRedirect
from sec.models import *
from django.shortcuts import render

# ONLY  Iplogs table is used in this script
def run_sql(request):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM IpLogs')
    return HttpResponseRedirect('/settings')  # Redirect to the IPLogs page after deleting all records

from django.http import HttpResponse

def count_iplogs(request):
    count = Iplogs.objects.count()
    return render(request, 'settings.html', {'count': count})

# ONLY Events table is used in this script
