from django.urls import path
from . import views
from .views import *
from .sql_views import *

urlpatterns = [ 
    # Pages
    path("", views.index),
    path("index", views.index, name=""),
    path("settings", views.settings, name="settings"),
    path("eventlog", views.eventlog, name="eventlog"),
    path("iplogs", views.iplogs, name="iplogs"),
    path('todo/', views.todo, name='todo'),
    path('filewatch', views.filewatch, name='filewatch'),
    path('news/', views.news, name='news'),

    # POST requests for IPLogs
    path('run_script/', views.run_script, name='run_script'),
    path('stop_script/', views.stop_script, name='stop_script'),

    # POST requests for EventLogs
    path('run-log-collector/', run_log_collector, name='run_log_collector'),
    path('stop-log-collector/', stop_log_collector, name='stop_log_collector'),

    path('run_sql/', views.run_sql, name='run_sql'), # POST requests for IPLogs Database
    path('clear_error_logs/', views.clear_error_logs, name='clear_error_logs'), # Clear Error Logs
    path('clear-event-logs/', views.clear_event_logs, name='clear_event_logs'), # Clear Event Logs
    path('clear_local_iplogs/', views.clear_local_iplogs, name='clear_local_iplogs'), # Clear "Local" IP Logs

    # POST requests for FileWatcher
    path('start_watch', views.start_watch, name='start_watch'),
    path('stop_watch', views.stop_watch, name='stop_watch'),
    path('clear_logs', views.clear_logs, name='clear_logs'), # Clear Logs
    path('get_file_logs', views.get_file_logs, name='get_file_logs'), # Get Logs for file watchers
    path('get-event-logs/', views.get_event_logs),  # Get Logs for eventlogs
    
    # Port Scanner
    path('port_scanner/', views.port_scanner, name='port_scanner'),
    path('port_results/', views.port_results, name='port_results'),

    # Task Controller
    path('task-controller/', views.task_controller, name='task_controller'),
    path('get-processes/', views.get_processes, name='get_processes'),
    path('kill-process/', views.kill_process, name='kill_process'),
    
]