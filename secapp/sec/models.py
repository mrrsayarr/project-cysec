from django.db import models

# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.

# Create your models here.

# class EventLog(models.Model):
#     ID = models.AutoField(primary_key=True)
#     EventID = models.IntegerField(null=True, blank=True)
#     SourceName = models.CharField(max_length=255, null=True, blank=True)
#     Level = models.IntegerField(null=True, blank=True)
#     Channel = models.CharField(max_length=255, null=True, blank=True)
#     Message = models.TextField(null=True, blank=True)
#     PredictedValue = models.FloatField(null=True, blank=True)
#     TimeGenerated = models.DateTimeField(null=True, blank=True)

#     def __str__(self):
#         return f"{self.EventID} || {self.PredictedValue} || {self.TimeGenerated}"

class Events(models.Model):
    ID = models.AutoField(primary_key=True) # Field name made lowercase.
    EventID = models.IntegerField(db_column='EventID', blank=True, null=True)  # Field name made lowercase.
    SourceName = models.TextField(db_column='SourceName', blank=True, null=True)  # Field name made lowercase.
    Level = models.TextField(db_column='Level', blank=True, null=True)  # Field name made lowercase.
    Channel = models.TextField(db_column='Channel', blank=True, null=True)  # Field name made lowercase.
    Message = models.TextField(db_column='Message', blank=True, null=True)  # Field name made lowercase.
    PredictedValue = models.TextField(db_column='PredictedValue', blank=True, null=True)  # Field name made lowercase. This field type is a guess.
    TimeGenerated = models.TextField(db_column='TimeGenerated', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = True
        db_table = 'events'

    def __str__(self):
        return f"{self.PredictedValue} ♦ {self.EventID}"

class Iplogs(models.Model):
    ID = models.AutoField(primary_key=True)  # Field name made lowercase.
    PID = models.IntegerField(db_column='PID', blank=True, null=True)  # Field name made lowercase.
    Process = models.TextField(db_column='Process', blank=True, null=True)  # Field name made lowercase.
    Local = models.TextField(db_column='Local', blank=True, null=True)  # Field name made lowercase.
    Remote = models.TextField(db_column='Remote', blank=True, null=True)  # Field name made lowercase.
    Protocol = models.TextField(db_column='Protocol', blank=True, null=True)  # Field name made lowercase.
    StartTime = models.TextField(db_column='StartTime', blank=True, null=True)  # Field name made lowercase.
    CommunicationProtocol = models.TextField(db_column='CommunicationProtocol', blank=True, null=True)  # Field name made lowercase.
    LocalIp = models.TextField(db_column='LocalIP', blank=True, null=True)  # Field name made lowercase.
    LocalPort = models.IntegerField(db_column='LocalPort', blank=True, null=True)  # Field name made lowercase.
    RemoteIp = models.TextField(db_column='RemoteIP', blank=True, null=True)  # Field name made lowercase.
    RemotePort = models.IntegerField(db_column='RemotePort', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = True
        db_table = 'IpLogs'

    def __str__(self):
        return f"{self.Process} ♦ {self.RemoteIp}"

class ErrorLogs(models.Model):
    id = models.AutoField(primary_key=True)  # Field name made lowercase.
    errormessage = models.TextField(db_column='ErrorMessage', blank=True, null=True)  # Field name made lowercase.
    errortime = models.TextField(db_column='ErrorTime', blank=True, null=True)  # Field name made lowercase. This field type is a guess.

    class Meta:
        managed = True
        db_table = 'error_logs'

class Eventdescription(models.Model):
    eventid = models.AutoField(primary_key=True)  # Field name made lowercase.
    description = models.TextField(db_column='Description', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = True
        db_table = 'eventdescription'

    def __str__(self):
        return f"{self.EventID} || {self.description}"

class FileLogs(models.Model):
    event_type = models.TextField(blank=True, null=True)
    file_path = models.TextField(blank=True, null=True)
    timestamp = models.TextField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'file_logs'

    def __str__(self):
        return f"{self.event_type} || {self.timestamp}"

class News(models.Model):
    id = models.AutoField(db_column='ID', primary_key=True)  # Field name made lowercase.
    sourcename = models.TextField(db_column='SourceName', blank=True, null=True)  # Field name made lowercase.
    title = models.TextField(db_column='Title', blank=True, null=True)  # Field name made lowercase.
    publishedat = models.TextField(db_column='PublishedAt', blank=True, null=True)  # Field name made lowercase.
    url = models.TextField(db_column='URL', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = True
        db_table = 'news'


class WatchPaths(models.Model):
    path = models.TextField()

    class Meta:
        managed = True
        db_table = 'watch_paths'

    def __str__(self):
        return f"{self.path}"
