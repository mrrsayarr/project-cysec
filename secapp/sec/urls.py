from django.urls import path
from . import views
from .views import *
from .sql_views import *
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from .views import LogoutViewWithGet
from django.urls import re_path

from django.conf.urls import handler404 
handler404 = 'sec.views.handler404' # Custom 404 Page

urlpatterns = [ 
    # Pages
    path("", views.index),        
    # path("", views.login_view, name="login"), # Default Page
    path("index", views.index, name=""),
    path("settings", views.settings, name="settings"),
    path("eventlog", views.eventlog, name="eventlog"),
    path("iplogs", views.iplogs, name="iplogs"),
    path('todo/', views.todo, name='todo'),
    path('filewatch', views.filewatch, name='filewatch'),
    path('news/', views.news, name='news'),

    # POST requests for Terminal Errors
    path('stream_terminal_output/<str:command>/', views.stream_terminal_output),

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
    path('get_ip_logs/', get_ip_logs, name='get_ip_logs'), # Get Logs for IPlogs
    
    # Port Scanner
    path('port_scanner/', views.port_scanner, name='port_scanner'),
    path('port_results/', views.port_results, name='port_results'),

    # Task Controller
    path('task-controller/', views.task_controller, name='task_controller'),
    path('get-processes/', views.get_processes, name='get_processes'),
    path('kill-process/', views.kill_process, name='kill_process'),
    
    path('search/', views.search, name='search'), # Search Page

    # ARP Monitor
    path('arp-scanner/', views.arp_scanner, name='arp_scanner'),
    path('arp_monitor/', views.arp_monitor, name='arp_monitor'),

    # Firewall Monitor
    path('firewall_monitor/', views.firewall_monitor, name='firewall_monitor'),
    path('get-firewall-logs/', views.get_firewall_logs, name='get_firewall_logs'),
    path('add-rule/', views.add_rule, name='add_rule'),
    path('edit-rule/<int:rule_id>/', views.edit_rule, name='edit_rule'),
    path('delete-rule/<int:rule_id>/', views.delete_rule, name='delete_rule'),

    # Login and Logout Pages
    path('login/', views.login_view, name='login'), 
    path('logout/', views.LogoutViewWithGet.as_view(next_page='/login'), name='logout'),  # LogoutViewWithGet kullan

    # Pages 
    re_path(r"^index/?$", views.index, name=""),
    re_path(r"^settings/?$", views.settings, name="settings"),
    re_path(r"^eventlog/?$", views.eventlog, name="eventlog"),
    re_path(r"^iplogs/?$", views.iplogs, name="iplogs"),
    re_path(r"^todo/?$", views.todo, name="todo"),
    re_path(r"^filewatch/?$", views.filewatch, name="filewatch"),
    re_path(r"^news/?$", views.news, name="news"),
    re_path(r"^port_scanner/?$", views.port_scanner, name="port_scanner"),
    re_path(r"^port_results/?$", views.port_results, name="port_results"),
    re_path(r"^task-controller/?$", views.task_controller, name="task_controller"),
    re_path(r"^search/?$", views.search, name="search"),
    re_path(r"^arp-scanner/?$", views.arp_scanner, name="arp_scanner"),
    re_path(r"^arp_monitor/?$", views.arp_monitor, name="arp_monitor"),
    re_path(r"^firewall_monitor/?$", views.firewall_monitor, name="firewall_monitor"),
    re_path(r"^add-rule/?$", views.add_rule, name="add_rule"),
    re_path(r"^edit-rule/(?P<rule_id>\d+)/?$", views.edit_rule, name="edit_rule"),
    re_path(r"^delete-rule/(?P<rule_id>\d+)/?$", views.delete_rule, name="delete_rule"),
    re_path(r"^login/?$", views.login_view, name="login"),
    re_path(r"^logout/?$", views.LogoutViewWithGet.as_view(next_page='/login'), name="logout"),

    # Functions
    re_path(r"^run_script/?$", views.run_script, name="run_script"),
    re_path(r"^stop_script/?$", views.stop_script, name="stop_script"),
    re_path(r"^run-log-collector/?$", run_log_collector, name="run_log_collector"),
    re_path(r"^stop-log-collector/?$", stop_log_collector, name="stop_log_collector"),
    re_path(r"^run_sql/?$", views.run_sql, name="run_sql"),
    re_path(r"^clear_error_logs/?$", views.clear_error_logs, name="clear_error_logs"),
    re_path(r"^clear_event_logs/?$", views.clear_event_logs, name="clear_event_logs"),
    re_path(r"^clear_local_iplogs/?$", views.clear_local_iplogs, name="clear_local_iplogs"),
    re_path(r"^start_watch/?$", views.start_watch, name="start_watch"),
    re_path(r"^stop_watch/?$", views.stop_watch, name="stop_watch"),
    re_path(r"^clear_logs/?$", views.clear_logs, name="clear_logs"),
    re_path(r"^get_file_logs/?$", views.get_file_logs, name="get_file_logs"),
    re_path(r"^get-event-logs/?$", views.get_event_logs, name="get_event_logs"),
    re_path(r"^get_ip_logs/?$", get_ip_logs, name="get_ip_logs"),
    re_path(r"^get-processes/?$", views.get_processes, name="get_processes"),
    re_path(r"^kill-process/?$", views.kill_process, name="kill_process"),
    re_path(r"^get-firewall-logs/?$", views.get_firewall_logs, name="get_firewall_logs"),
]