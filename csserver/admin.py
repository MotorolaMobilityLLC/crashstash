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

"""CrashStash Server admin.py"""

__author__ = "Tyson Smith"

from django.contrib import admin
from csserver.models import *

#TODO: Add init page
class ClassificationAdmin(admin.ModelAdmin):
    list_display = ('display', 'value')

class ClientAdmin(admin.ModelAdmin):
    list_display = ('approved', 'ip_addr', 'last_seen', 'mac_addr', 'platform')

class ClientVersionAdmin(admin.ModelAdmin):
    list_display = ('age', 'version_string')
    list_filter = ['version']

class PluginAdmin(admin.ModelAdmin):
    list_display = ('name', 'platform', 'weight')

class PluginTestAdmin(admin.ModelAdmin):
    list_display = ('allow_fuzzing', 'plugin', 'test')

class PluginVersionAdmin(admin.ModelAdmin):
    list_display = ('date', 'duration', 'iterations', 'name', 'plugin')

class ResultAdmin(admin.ModelAdmin):
    list_display = ('classification', 'count', 'defect',
                    'failure', 'plugin', 'triage_state')

class TestAdmin(admin.ModelAdmin):
    list_display = ('file_hash', 'is_private', 'name')

class TriageStateAdmin(admin.ModelAdmin):
    list_display = ('name',)

class WorkUnitAdmin(admin.ModelAdmin):
    list_display = ('client', 'created_time', 'duration',
                    'iterations', 'plugin_test', 'plugin_version')

admin.site.register(Classification, ClassificationAdmin)
admin.site.register(Client, ClientAdmin)
admin.site.register(ClientVersion, ClientVersionAdmin)
admin.site.register(Plugin, PluginAdmin)
admin.site.register(PluginTest, PluginTestAdmin)
admin.site.register(PluginVersion, PluginVersionAdmin)
admin.site.register(Result, ResultAdmin)
admin.site.register(Test, TestAdmin)
admin.site.register(TriageState, TriageStateAdmin)
admin.site.register(WorkUnit, WorkUnitAdmin)