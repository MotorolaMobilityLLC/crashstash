# Copyright 2015 Motorola Mobility
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""
CrashStash Server models.py

This defines the data models and the relationships between them.
"""

__author__ = "Tyson Smith"

import datetime
import hashlib
import os
from django.db import models
from django.db.models.signals import pre_delete
from django.dispatch.dispatcher import receiver

class Classification(models.Model):
    display = models.CharField(max_length=64, unique=True)
    value = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return self.display

class Client(models.Model):
    approved = models.BooleanField(default=False)
    ip_addr = models.GenericIPAddressField()
    last_seen = models.DateTimeField(auto_now=True)
    mac_addr = models.CharField(max_length=20)
    platform = models.CharField(max_length=64)

    class Meta:
        unique_together = ('ip_addr', 'mac_addr')

    def __str__(self):
        return ' - '.join([self.ip_addr, self.mac_addr])

class ClientVersion(models.Model):
    data = models.FileField(max_length=256, upload_to='client_version')
    version = models.DateTimeField(auto_now_add=True)

    def age(self):
        d = datetime.datetime.now() - self.version.replace(tzinfo=None)
        return datetime.timedelta(seconds=int(d.total_seconds()))

    def version_string(self):
        return self.version.strftime('%Y%m%d.%H.%M.%S')

    def __str__(self):
        return self.version_string()

@receiver(pre_delete, sender=ClientVersion)
def ClientVersion_delete(sender, instance, **kwargs):
    if os.path.isfile(instance.data.name):
        instance.data.delete(False)

class Plugin(models.Model):
    data = models.FileField(max_length=64, upload_to='plugins')
    name = models.SlugField(unique=True)
    platform = models.SlugField()
    weight = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return self.name

class Test(models.Model):
    data = models.FileField(max_length=1024, upload_to='test_cases')
    file_hash = models.CharField(max_length=64, unique=True)
    is_private = models.ForeignKey(Plugin, blank=True, null=True, related_name='+')
    name = models.TextField()

    def __str__(self):
        return self.name

class PluginTest(models.Model):
    allow_fuzzing = models.BooleanField(default=True)
    plugin = models.ForeignKey(Plugin)
    test = models.ForeignKey(Test)

    def __str__(self):
        return self.test.name

class PluginVersion(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    duration = models.BigIntegerField(default=0)
    iterations = models.BigIntegerField(default=0)
    plugin = models.ForeignKey(Plugin)
    name = models.SlugField()

    class Meta:
        unique_together = ('plugin', 'name')

    def __str__(self):
        return self.name


class SystemErrorType(models.Model):
    name = models.CharField(max_length=64, unique=True)

class SystemErrorReport(models.Model):
    count = models.PositiveIntegerField(default=0)
    first = models.DateTimeField(auto_now_add=True)
    last = models.DateTimeField(auto_now=True)
    log = models.TextField()
    type = models.ForeignKey(SystemErrorType)

class SystemSetting(models.Model):
    work_duration = models.PositiveIntegerField(default=1200)

class Tag(models.Model):
    name = models.SlugField(unique=True)

class TestTags(models.Model):
    tag = models.ForeignKey(Tag)
    test = models.ForeignKey(Test)

class TriageState(models.Model):
    name = models.CharField(max_length=64, unique=True)
    # Triage State names
    # - Ignored
    # - Logged
    # - New
    # - Not Reproducible
    # - Refresh
    def __str__(self):
        return self.name

class Result(models.Model):
    classification = models.ForeignKey(Classification)
    count = models.PositiveIntegerField(default=0)
    data = models.FileField(max_length=1024, upload_to='results')
    defect = models.CharField(max_length=64)
    failure = models.CharField(max_length=64)
    file_hash = models.CharField(max_length=64)
    found_first = models.DateTimeField(auto_now_add=True)
    found_last = models.DateTimeField(auto_now=True)
    log = models.TextField(null=True)
    plugin = models.ForeignKey(Plugin)
    name = models.CharField(max_length=1024)
    triage_state = models.ForeignKey(TriageState)

    class Meta:
        unique_together = (
            ('classification', 'failure', 'plugin'),
        )

class WorkUnit(models.Model):
    client = models.ForeignKey(Client)
    created_time = models.DateTimeField(auto_now_add=True)
    duration = models.PositiveIntegerField(default=0)
    end_time = models.DateTimeField(null=True)
    iterations = models.PositiveIntegerField(default=0)
    plugin_test = models.ForeignKey(PluginTest, default=None, null=True)
    plugin_version = models.ForeignKey(PluginVersion)
    #result = models.ForeignKey(Result, default=None, null=True)
