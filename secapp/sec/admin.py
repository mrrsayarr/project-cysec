from django.contrib import admin
from .models import Events, Iplogs

# Register your models here.
# For Only Admin Panel

admin.site.register(Events)
admin.site.register(Iplogs)
