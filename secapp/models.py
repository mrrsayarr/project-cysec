# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class Iplogs(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    pid = models.IntegerField(db_column='PID', blank=True, null=True)  # Field name made lowercase.
    process = models.TextField(db_column='Process', blank=True, null=True)  # Field name made lowercase.
    local = models.TextField(db_column='Local', blank=True, null=True)  # Field name made lowercase.
    remote = models.TextField(db_column='Remote', blank=True, null=True)  # Field name made lowercase.
    protocol = models.TextField(db_column='Protocol', blank=True, null=True)  # Field name made lowercase.
    starttime = models.TextField(db_column='StartTime', blank=True, null=True)  # Field name made lowercase.
    communicationprotocol = models.TextField(db_column='CommunicationProtocol', blank=True, null=True)  # Field name made lowercase.
    localip = models.TextField(db_column='LocalIP', blank=True, null=True)  # Field name made lowercase.
    localport = models.IntegerField(db_column='LocalPort', blank=True, null=True)  # Field name made lowercase.
    remoteip = models.TextField(db_column='RemoteIP', blank=True, null=True)  # Field name made lowercase.
    remoteport = models.IntegerField(db_column='RemotePort', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'IpLogs'


class ErrorLogs(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    errormessage = models.TextField(db_column='ErrorMessage', blank=True, null=True)  # Field name made lowercase.
    errortime = models.TextField(db_column='ErrorTime', blank=True, null=True)  # Field name made lowercase. This field type is a guess.

    class Meta:
        managed = False
        db_table = 'error_logs'


class Eventdescription(models.Model):
    eventid = models.AutoField(db_column='EventID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    description = models.TextField(db_column='Description', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'eventdescription'


class Events(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    eventid = models.IntegerField(db_column='EventID', blank=True, null=True)  # Field name made lowercase.
    sourcename = models.TextField(db_column='SourceName', blank=True, null=True)  # Field name made lowercase.
    level = models.TextField(db_column='Level', blank=True, null=True)  # Field name made lowercase.
    channel = models.TextField(db_column='Channel', blank=True, null=True)  # Field name made lowercase.
    message = models.TextField(db_column='Message', blank=True, null=True)  # Field name made lowercase.
    predictedvalue = models.TextField(db_column='PredictedValue', blank=True, null=True)  # Field name made lowercase. This field type is a guess.
    timegenerated = models.TextField(db_column='TimeGenerated', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'events'


class FileLogs(models.Model):
    event_type = models.TextField(blank=True, null=True)
    file_path = models.TextField(blank=True, null=True)
    timestamp = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'file_logs'


class News(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    sourcename = models.TextField(db_column='SourceName', blank=True, null=True)  # Field name made lowercase.
    title = models.TextField(db_column='Title', blank=True, null=True)  # Field name made lowercase.
    publishedat = models.TextField(db_column='PublishedAt', blank=True, null=True)  # Field name made lowercase.
    url = models.TextField(db_column='URL', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'news'


class WatchPaths(models.Model):
    path = models.TextField()

    class Meta:
        managed = False
        db_table = 'watch_paths'
# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class Iplogs(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    pid = models.IntegerField(db_column='PID', blank=True, null=True)  # Field name made lowercase.
    process = models.TextField(db_column='Process', blank=True, null=True)  # Field name made lowercase.
    local = models.TextField(db_column='Local', blank=True, null=True)  # Field name made lowercase.
    remote = models.TextField(db_column='Remote', blank=True, null=True)  # Field name made lowercase.
    protocol = models.TextField(db_column='Protocol', blank=True, null=True)  # Field name made lowercase.
    starttime = models.TextField(db_column='StartTime', blank=True, null=True)  # Field name made lowercase.
    communicationprotocol = models.TextField(db_column='CommunicationProtocol', blank=True, null=True)  # Field name made lowercase.
    localip = models.TextField(db_column='LocalIP', blank=True, null=True)  # Field name made lowercase.
    localport = models.IntegerField(db_column='LocalPort', blank=True, null=True)  # Field name made lowercase.
    remoteip = models.TextField(db_column='RemoteIP', blank=True, null=True)  # Field name made lowercase.
    remoteport = models.IntegerField(db_column='RemotePort', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'IpLogs'


class ErrorLogs(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    errormessage = models.TextField(db_column='ErrorMessage', blank=True, null=True)  # Field name made lowercase.
    errortime = models.TextField(db_column='ErrorTime', blank=True, null=True)  # Field name made lowercase. This field type is a guess.

    class Meta:
        managed = False
        db_table = 'error_logs'


class Eventdescription(models.Model):
    eventid = models.AutoField(db_column='EventID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    description = models.TextField(db_column='Description', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'eventdescription'


class Events(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    eventid = models.IntegerField(db_column='EventID', blank=True, null=True)  # Field name made lowercase.
    sourcename = models.TextField(db_column='SourceName', blank=True, null=True)  # Field name made lowercase.
    level = models.TextField(db_column='Level', blank=True, null=True)  # Field name made lowercase.
    channel = models.TextField(db_column='Channel', blank=True, null=True)  # Field name made lowercase.
    message = models.TextField(db_column='Message', blank=True, null=True)  # Field name made lowercase.
    predictedvalue = models.TextField(db_column='PredictedValue', blank=True, null=True)  # Field name made lowercase. This field type is a guess.
    timegenerated = models.TextField(db_column='TimeGenerated', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'events'


class FileLogs(models.Model):
    event_type = models.TextField(blank=True, null=True)
    file_path = models.TextField(blank=True, null=True)
    timestamp = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'file_logs'


class News(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True, blank=True, null=True)  # Field name made lowercase.
    sourcename = models.TextField(db_column='SourceName', blank=True, null=True)  # Field name made lowercase.
    title = models.TextField(db_column='Title', blank=True, null=True)  # Field name made lowercase.
    publishedat = models.TextField(db_column='PublishedAt', blank=True, null=True)  # Field name made lowercase.
    url = models.TextField(db_column='URL', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'news'


class WatchPaths(models.Model):
    path = models.TextField()

    class Meta:
        managed = False
        db_table = 'watch_paths'
