# Generated by Django 5.0.6 on 2024-07-02 11:05

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='EventLog',
            fields=[
                ('ID', models.AutoField(primary_key=True, serialize=False)),
                ('EventID', models.IntegerField(blank=True, null=True)),
                ('SourceName', models.CharField(blank=True, max_length=255, null=True)),
                ('Level', models.IntegerField(blank=True, null=True)),
                ('Channel', models.CharField(blank=True, max_length=255, null=True)),
                ('Message', models.TextField(blank=True, null=True)),
                ('PredictedValue', models.FloatField(blank=True, null=True)),
                ('TimeGenerated', models.DateTimeField(blank=True, null=True)),
            ],
        ),
    ]
