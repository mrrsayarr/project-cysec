from django.urls import path
from . import views
from .views import *
from .sql_views import *

urlpatterns = [ 
    path("", views.index),
    path("index", views.index, name=""),
    path("settings", views.settings, name="settings"),
    path("eventlog", views.eventlog, name="eventlog"),
    path("iplogs", views.iplogs, name="iplogs"),
    path('todo/', views.todo, name='todo'),

    # POST requests for IPLogs
    path('run_script/', views.run_script, name='run_script'),
    path('stop_script/', views.stop_script, name='stop_script'),

    path('run_sql/', views.run_sql, name='run_sql'), # POST requests for IPLogs Database

    # POST requests for EventLogs
    path('run-log-collector/', run_log_collector, name='run_log_collector'),
    path('stop-log-collector/', stop_log_collector, name='stop_log_collector'),

    path('clear_error_logs/', views.clear_error_logs, name='clear_error_logs'), # Clear Error Logs
    path('clear-event-logs/', views.clear_event_logs, name='clear_event_logs'), # Clear Event Logs

]