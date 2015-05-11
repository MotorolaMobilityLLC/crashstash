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
CrashStash Server views.py

This handles the management and distribution of clients, plug-ins, work and
results as well as communication with clients.
"""

__author__ = "Tyson Smith"

import datetime
import hashlib
import json
import os
import random
import re
from csserver.models import Classification, Client, ClientVersion, Plugin
from csserver.models import PluginTest, PluginVersion, Result, TriageState, WorkUnit
from django.http import HttpResponse, HttpResponseBadRequest
from django.core.servers.basehttp import FileWrapper
from django.views.generic import View

class BaseWorkView(View):
    client = None
    pl_version = None
    work_unit = None

    def get(self, request, *args, **kwargs):
        # by default get requests are ignored
        return HttpResponseBadRequest()

    @staticmethod
    def _is_client_version_active(report_version):
        try:
            lastest_version = ClientVersion.objects.order_by('-version')[:1][0]
        except IndexError:
            # this is a configuration issue add a CV to the db
            # TODO: this should include a notification to the sys admin
            return False
        return lastest_version.version_string() == report_version

    @staticmethod
    def is_valid_mac_addr(token):
        return re.match(r'^([A-F0-9]{2}[:-]){5}[A-F0-9]{2}$', token) is not None

    def _validate_client(self, request):
        """
        Validate incoming client request. This is used for client management
        and tracking. It is used to help identify and track client work
        request and reports.

        NOTE: This is not meant to be a security mechanism.
        """

        if not request.META.get('REMOTE_ADDR', None):
            return
        mac = request.POST.get('mac', '')[:17].upper()
        if not self.is_valid_mac_addr(mac):
            return
        try:
            self.client = Client.objects.get(
                mac_addr=mac,
                ip_addr=request.META.get('REMOTE_ADDR')
            )
        except Client.DoesNotExist:
            platform = request.POST.get('platform', '')[:64]
            if not platform:
                return
            self.client = Client(
                mac_addr=mac,
                ip_addr=request.META.get('REMOTE_ADDR'),
                platform=platform.lower()
            )
        # save to update last seen date even if client exists
        self.client.save()

class WorkRequestView(BaseWorkView):
    """
    WorkRequestView handles client requests and responds with one of the
    following responses:
     - client update
     - plugin update
     - work unit

    If an appropriate response is unavailable a HttpResponseBadRequest is sent.
    """

    plugin = None

    def post(self, request, *args, **kwargs):
        self._validate_client(request)
        if self.client is None or not self.client.approved:
            return HttpResponseBadRequest()

        if not self._is_client_version_active(request.POST.get('client_version', '')[:100]):
            # client update required
            return self._response_client_update()

        self._choose_active_plugin(
            request.POST.get('plugin_versions', '')[:100000],
            request.POST.get('plugin_request', '')[:100]
        )
        if not self.plugin:
            # no project available for platform
            return HttpResponseBadRequest()
        if not self.pl_version:
            # update plug-in required
            return self._response_plugin_update()

        self._get_work_unit()
        if not self.work_unit:
            return HttpResponseBadRequest()

        return self._response_work_unit()

    @staticmethod
    def _response_client_update():
        try:
            cv = ClientVersion.objects.order_by('-version')[:1][0]
        except IndexError:
            # this is a configuration issue add a ClientVersion to the db
            return HttpResponseBadRequest()
        wrapper = FileWrapper(cv.data)
        response = HttpResponse(wrapper, content_type='application/x-gzip')
        response['Content-Transfer-Encoding'] = 'binary'
        response['Content-Disposition'] = 'attachment; filename="client_update.tar.gz"'
        response['Content-Length'] = os.path.getsize(cv.data.name)
        response['client_version'] = cv.version_string()
        return response

    def _response_plugin_update(self):
        try:
            pv = PluginVersion.objects.filter(plugin=self.plugin).order_by('-date')[:1][0]
        except IndexError:
            # this is a configuration issue add a PluginVersion to the db
            return HttpResponseBadRequest()
        wrapper = FileWrapper(self.plugin.data)
        response = HttpResponse(wrapper, content_type='application/x-gzip')
        response['Content-Transfer-Encoding'] = 'binary'
        response['Content-Disposition'] = 'attachment; filename="plugin_update.tar.gz"'
        response['Content-Length'] = os.path.getsize(self.plugin.data.name)
        response['plugin_name'] = self.plugin.name
        response['plugin_version'] = pv.name
        return response

    def _response_work_unit(self):
        if self.work_unit.plugin_test is not None:
            # Normal work
            wrapper = FileWrapper(self.work_unit.plugin_test.test.data)
            response = HttpResponse(wrapper, content_type='application/octet-stream')
            response['Content-Transfer-Encoding'] = 'binary'
            response['Content-Disposition'] = 'attachment; filename="%s"' % (self.work_unit.plugin_test.test.data.name)
            response['Content-Length'] = os.path.getsize(self.work_unit.plugin_test.test.data.name)
            response['plugin_name'] = self.plugin.name
            response['test_name'] = self.work_unit.plugin_test.test.name
            response['test_hash'] = self.work_unit.plugin_test.test.file_hash
            response['duration'] = self.work_unit.duration
            response['iterations'] = self.work_unit.iterations
            response['allow_fuzzing'] = '1' if self.work_unit.plugin_test.allow_fuzzing else '0'
        elif self.work_unit.result is not None:
            # Refresh work
            wrapper = FileWrapper(self.work_unit.result.data)
            response = HttpResponse(wrapper, content_type='application/octet-stream')
            response['Content-Transfer-Encoding'] = 'binary'
            response['Content-Disposition'] = 'attachment; filename="%s"' % (self.work_unit.result.data.name)
            response['Content-Length'] = os.path.getsize(self.work_unit.result.data.name)
            response['plugin_name'] = self.plugin.name
            response['test_name'] = self.work_unit.result.name
            response['test_hash'] = self.work_unit.result.file_hash
            response['duration'] = self.work_unit.duration
            response['iterations'] = self.work_unit.iterations
        else:
            # This should never happen
            response = HttpResponseBadRequest()
        return response

    def _get_work_unit(self):
        self.work_unit = WorkUnit(
            client=self.client,
            plugin_version=self.pl_version
        )
        # IDEA: possibly randomly run a non-repro as a fuzzable???
        try:
            # look for refresh work
            tr_state = TriageState.objects.get(name='Refresh')
            self.work_unit.result = Result.objects.filter(plugin=self.plugin, triage_state=tr_state).order_by('?')[:1][0]
            # this isn't perfect (worst case a few clients refresh the same result)
            self.work_unit.result.triage_state = TriageState.objects.get(name='Not Reproducible')
            self.work_unit.result.save()
        except (IndexError, TriageState.DoesNotExist):
            # No refresh work
            try:
                self.work_unit.plugin_test = PluginTest.objects.filter(plugin=self.plugin).order_by('?')[:1][0]
            except IndexError:
                # No regular work... This should never happen because of the earlier checks in _choose_active_plugin()
                self.work_unit = None
                return
        # TODO: check if test case file exists
        if self.work_unit.plugin_test and self.work_unit.plugin_test.allow_fuzzing:
            # TODO: use db for duration value
            self.work_unit.duration = 1200
            self.work_unit.iterations = 0
        else:
            self.work_unit.duration = 0
            self.work_unit.iterations = 1

        self.work_unit.save()

    def _choose_active_plugin(self, plugin_versions, requested_pl=None):
        if requested_pl:
            try:
                self.plugin = Plugin.objects.get(name=requested_pl, platform=self.client.platform)
                if not PluginTest.objects.filter(plugin=self.plugin).exists():
                    self.plugin = None
            except Plugin.DoesNotExist:
                self.plugin = None
            if self.plugin is None:
                return
        else:
            pl_ts = PluginTest.objects.values('plugin').distinct()
            choices = list()
            for plugin in Plugin.objects.only('id', 'weight').filter(pk__in=pl_ts, platform=self.client.platform, weight__gt=0).iterator():
                choices.extend([plugin.id for _ in range(plugin.weight)])
            try:
                self.plugin = Plugin.objects.get(id=random.choice(choices))
            except (IndexError, Plugin.DoesNotExist):
                return

        # Now get the PluginVersion object
        try:
            pv = PluginVersion.objects.filter(
                plugin=self.plugin
            ).order_by('-date')[:1][0]
            if pv.name == json.loads(plugin_versions).get(self.plugin.name, None):
                self.pl_version = pv
        except (AttributeError, IndexError, RuntimeError, TypeError, ValueError):
            return

class WorkReportView(BaseWorkView):
    """WorkReportView handles client work reports."""

    def post(self, request, *args, **kwargs):
        self._validate_client(request)
        if self.client is None or not self.client.approved:
            return HttpResponseBadRequest()
        self._look_up_work_unit(request)
        if not self.pl_version:
            return HttpResponseBadRequest()
        if not self._log_result(request):
            return HttpResponseBadRequest()
        return HttpResponse()


    def _log_result(self, request):
        """
        Parses incoming client request and processes results.

        Results are handled depending on their current state in the database.
        New results are added to the database. Existing results will have
        their count, triage state, test case and log data updated. Result dates
        are updated automatically (see modules.py).
        """

        if not request.POST.get('has_result', False):
            return True
        try:
            # check hashes
            defect = request.POST['defect'][:40].lower()
            failure = request.POST['failure'][:40].lower()
            file_hash = request.POST['result_hash'][:40].lower()
        except KeyError:
            return True
        if not file_hash or not defect or not failure:
            return True
        try:
            classification = Classification.objects.get(
                value=request.POST.get('classification', 'UNKNOWN')
            )
        except Classification.DoesNotExist:
            classification = Classification.objects.get(value='UNKNOWN')

        try:
            # every failure/classification/plug-in combination is unique
            result = Result.objects.get(
                classification=classification,
                failure=failure,
                plugin=self.pl_version.plugin
            )
            if result.defect != defect:
                # TODO: report an error? This is a problem on the client side.
                # Typically a failures should not have multiple defects, however a defect may be
                # exposed by multiple unique failures. In other words the defect is derived from the
                # failure so a failure should not have more than one defect.
                return False
            # handle triage states of known results
            if result.triage_state.name in ('Ignored', 'Logged'):
                return True
            elif result.triage_state.name in ('Not Reproducible', 'Refresh'):
                if not PluginVersion.objects.filter(date__gt=self.pl_version.date, plugin=self.pl_version.plugin).exists():
                    # verify the result was reported from the latest plug-in version
                    result.triage_state = TriageState.objects.get(name='New')
                else:
                    result.triage_state = TriageState.objects.get(name='Refresh')
            elif PluginVersion.objects.filter(date__gt=self.pl_version.date, plugin=self.pl_version.plugin).exists():
                result.triage_state = TriageState.objects.get(name='Refresh')
            old_test_case = result.data.name
        except Result.DoesNotExist:
            old_test_case = None
            result = Result()
            result.classification = classification
            result.defect = defect
            result.failure = failure
            result.plugin = self.pl_version.plugin
            result.triage_state = TriageState.objects.get(name='New')

        try:
            result.count += max(int(request.POST.get('count', '1')[:5]), 1)
            result.count = min(0x7FFFFFFFFFFFFFFF, result.count)
        except ValueError:
            return True

        result.log = request.POST.get('log', None)
        if result.log:
            # limit log size to 512K
            result.log = result.log.strip()[:524288]

        if result.file_hash == file_hash and result.failure == failure and result.classification == classification:
            # failure has been logged with this test case data
            result.save()
            return True

        result.file_hash = file_hash

        # .name allows using a name other than what is used to store it on the file system
        if request.POST.get('name', None) is not None:
            result.name = request.POST.get('name')[:1024]
        elif request.POST.get('file_name', None) is not None:
            result.name = request.POST.get('file_name')[:1024]
        result.data = request.FILES.get('attachment', None)
        if not result.data:
            return False # missing a test case
        file_hash = hashlib.sha1()
        while True:
            hash_data = result.data.read(65536) # 64K
            if not hash_data:
                break
            file_hash.update(hash_data)
        # check for file hash collision
        if file_hash.hexdigest() == result.file_hash:
            result.save()
            if old_test_case and os.path.isfile(old_test_case):
                os.remove(old_test_case)
        else:
            # hash check failed set new test case for removal
            # since result.save() is not called the test case will not be written to disk
            return False
        return True

    def _look_up_work_unit(self, request):
        """
        Looks up and sets self.work_unit to the WorkUnit object referenced in
        the incoming request. If no WorkUnit is found self.work_unit is
        set to None.
        """

        try:
            # look up plug-in version to help identify replay results
            self.pl_version = PluginVersion.objects.get(
                name=request.POST['plugin_version'][:50],
                plugin=Plugin.objects.get(name=request.POST['plugin_name'][:50])
            )
            try:
                self.work_unit = WorkUnit.objects.filter(
                    client=self.client,
                    plugin_version=self.pl_version
                ).order_by('-created_time')[:1][0]
            except IndexError:
                pass
            if self.work_unit and self.work_unit.end_time is None:
                # mark complete
                try:
                    self.work_unit.duration = max(int(request.POST['duration'][:10]), 0)
                    self.work_unit.iterations = max(int(request.POST['iterations'][:10]), 0)
                except (KeyError, TypeError, ValueError):
                    self.work_unit.duration = self.work_unit.duration if self.work_unit.duration else 0
                    self.work_unit.iterations = 0
                self.work_unit.duration = min(self.work_unit.duration, 0x7FFFFFFF)
                self.work_unit.iterations = min(self.work_unit.iterations, 0x7FFFFFFF)
                self.work_unit.end_time = datetime.datetime.now()
                self.pl_version.duration += self.work_unit.duration
                self.pl_version.iterations += self.work_unit.iterations
                self.work_unit.save()
                self.pl_version.save()
        except (KeyError, Plugin.DoesNotExist, PluginVersion.DoesNotExist):
            # invalid work unit, maybe incomplete or previously reported
            self.pl_version = None
            self.work_unit = None


