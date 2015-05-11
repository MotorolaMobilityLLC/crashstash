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

"""CrashStash Server URLs"""

__author__ = "Tyson Smith"

from django.conf.urls import patterns, url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = patterns(
	'',
    url(r'^workrequest/$', csrf_exempt(views.WorkRequestView.as_view()), name='request'),
    url(r'^workreport/$', csrf_exempt(views.WorkReportView.as_view()), name='report'),
)