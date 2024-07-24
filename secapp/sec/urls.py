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
    
]