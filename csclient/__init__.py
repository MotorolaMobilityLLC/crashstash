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
CrashStash client

This module enables the distribution of work from a CrashStash server.
It enables:
 - collection and organization of test results
 - requesting and reporting work/results
 - automatic plugin management
"""

__author__ = "Tyson Smith"

import hashlib
import http.client
import json
import os
import platform
import requests
import shutil
import socket
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid


class WorkUnit(object):
    """Used to organize information for communication with CrashStash server."""
    allow_fuzzing = None
    duration = None
    iterations = None
    plugin = None
    test_file = None
    test_hash = None
    test_name = None


class POSTRequestManager(object):
    """POSTRequestManager simplifies POST request made to the server."""
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.response = None

    def __enter__(self):
        self.response = requests.post(**self.kwargs)
        return self.response

    def __exit__(self, exc1, exc2, exc3):
        if self.response:
            self.response.close()


class Client(object):
    """CrashStash Client for requesting and reporting work/results."""
    _client_update = 'client_update.tar.gz'
    _plugin_update = 'plugin_update.tar.gz'

    def __init__(
            self,
            addr='127.0.0.1',
            cert=None,
            debug=False,
            port=8000,
            scheme='https',
            timeout=120,
            version_file='version.json'
        ):
        """
        addr - string containing the IP address or DNS of the CrashStash
        server that will be used.

        cert - path to the certificate that will be used to verify
        the identity of the server.
        WARNING: if https is used and no certificate is provided the
        server certificate will not be verified!

        debug - if set request data is written to disk for analysis.

        port - integer containing the port number to connect to on
        the CrashStash server.

        scheme - tells the client to make either http or https connections
        to the server.

        timeout - amount of time to wait to receive data before
        closing the connection.
        NOTE: This should not be changed unless there are issues
        with the default.

        version_file - string containing the name of the file that holds
        the configuration information.
        """
        self.status_code = None
        self._addr = addr
        self._debug = debug
        self._port = port
        self._scheme = 'http' if scheme.lower() == 'http' else 'https'
        self._timeout = timeout
        self._version_file = version_file

        if self._scheme == 'https' and cert:
            cert = os.path.abspath(cert)
            with open(cert, 'r') as _:
                pass # verify the file exists and is readable
            self._verify = cert
        else:
            self._verify = False

        try:
            with open(self._version_file, 'r') as fp:
                self._versions = json.load(fp)
        except (IOError, TypeError, ValueError):
            self._versions = {
                'client_pending_update':'',
                'client_version':'',
                'plugin_pending_update':None,
                'plugin_versions':dict()
            }

    @staticmethod
    def _get_mac_addr():
        """Returns a string containing MAC address (XX:XX:XX:XX:XX:XX)."""
        mac_addr = '%012X' % uuid.getnode()
        return ':'.join([mac_addr[i:i+2] for i in range(0, len(mac_addr), 2)])

    @staticmethod
    def _get_platform():
        """
        Returns a string with the OS name and architecture.

        ex. 'Linux-x86_64' or 'Windows-AMD64'
        """
        uname = platform.uname()
        return '-'.join([uname[0], uname[4]]).lower()

    def _get_url(self, loc):
        return urllib.parse.urlunsplit(
            (self._scheme, '%s:%d' % (self._addr, self._port), loc, '', '')
        )

    def _save_versions(self):
        with open(self._version_file, 'w') as fp:
            fp.write(json.dumps(self._versions, indent=2))

    @staticmethod
    def _download_file(response, file_name=None, sha1=None):
        fd, working_fname = tempfile.mkstemp()
        os.close(fd)
        if file_name:
            shutil.move(working_fname, os.path.join(os.getcwd(), file_name))
            working_fname = file_name
        with open(working_fname, 'w+b') as fp:
            fp.write(response.content)
            fp.seek(0)
            if sha1 is not None:
                file_sha1 = hashlib.sha1(fp.read())
        if sha1 is not None and sha1 != file_sha1.hexdigest():
            # hash check failed
            os.remove(working_fname)
            return None
        return working_fname


    def get_client_version(self):
        """Retrieves client version."""
        return self._versions.get('client_version', '')

    def get_plugin_version(self, pl_name):
        """
        Retrieves plugin version.

        The pl_name argument is the name of the plugin that will be queried.

        Returns either a version string or an empty string.
        """
        try:
            return self._versions['plugin_versions'][pl_name]
        except KeyError:
            return ''

    def required_client_update(self):
        """
        Checks if there is a pending client update.

        Returns a tuple containing the update version string and a string
        containing the absolute file path if an update is available
        otherwise None is returned.
        """
        try:
            if self._versions['client_pending_update'] and os.path.isfile(self._client_update):
                return (self._versions['client_pending_update'], self._client_update)
        except KeyError:
            pass
        return None

    def required_plugin_update(self):
        """
        Checks for a pending plugin update.

        Returns a tuple containing the plugin in name, update version string and
        a string containing the absolute file path if an update is available
        otherwise None is returned.
        """
        try:
            if self._versions['plugin_pending_update'] and os.path.isfile(self._plugin_update):
                pl_name, pl_version = self._versions['plugin_pending_update']
                return pl_name, pl_version, self._plugin_update
        except (KeyError, ValueError):
            pass
        return None

    def request(self, loc='/crashstash/workrequest/', plugin=None):
        """
        Requests work from a CrashStash Server.

        loc - location on the server that will be queried for that WorkUnit.

        plugin - request work for a specific plugin by name.

        Returns a :class:`~WorkUnit` or None if the request is
        unsuccessful.
        """
        try:
            data = {
                'client_version':self._versions.get('client_version', ''),
                'mac':self._get_mac_addr(),
                'platform':self._get_platform(),
                'plugin_request':plugin if plugin is not None else '',
                'plugin_versions':json.dumps(
                    self._versions.get('plugin_versions', ''))
            }

            with POSTRequestManager(data=data,
                                    timeout=self._timeout,
                                    url=self._get_url(loc),
                                    verify=self._verify) as r:
                self.status_code = r.status_code
                if r.status_code != 200:
                    if r.status_code == 500 and self._debug:
                        with open('debug_report.html', 'w') as fp:
                            fp.write(r.text)
                    return None
                if r.headers.get('client_version', None):
                    if self._download_file(r, file_name=self._client_update):
                        self._versions['client_pending_update'] = r.headers.get('client_version')
                        self._save_versions()
                    return None
                elif r.headers.get('plugin_version', None) and r.headers.get('plugin_name', None):
                    if self._download_file(r, file_name=self._plugin_update):
                        plugin_name = r.headers.get('plugin_name')[:50]
                        self._versions['plugin_pending_update'] = (plugin_name, r.headers.get('plugin_version')[:50])
                        self._save_versions()
                    return None
                elif not r.headers.get('test_name', None) or not r.headers.get('plugin_name', None):
                    return None

                wu = WorkUnit()
                wu.plugin = r.headers.get('plugin_name', '')[:50]
                wu.allow_fuzzing = bool(int(r.headers.get('allow_fuzzing', '0')[:1]))
                wu.duration = max(int(r.headers.get('duration', '0')), 0)
                wu.iterations = max(int(r.headers.get('iterations', '0')), 0)
                wu.test_hash = r.headers.get('test_hash', '')[:64]
                wu.test_name = r.headers.get('test_name', '')[:1024]
                wu.test_file = self._download_file(r, sha1=wu.test_hash)
            if wu.test_file is not None:
                return wu
        except (AttributeError, requests.exceptions.ConnectionError,
                socket.timeout, ValueError):
            self.status_code = None
        return None

    def report_work(self, wu, loc='/crashstash/workreport/'):
        """
        Used to report a :class:`~WorkUnit` to a CrashStash Server.

        wu - :class:`~WorkUnit` that holds the details for work completed by
        the client that will be reported to the server.

        loc - location on the server that :class:`~WorkUnit` will be reported to.

        Returns True if successful or False on a failed attempt.
        """
        try:
            data = {
                'duration':wu.duration,
                'iterations':wu.iterations,
                'mac':self._get_mac_addr(),
                'plugin_name':wu.plugin,
                'plugin_version':self._versions['plugin_versions'][wu.plugin]
            }
            with POSTRequestManager(data=data,
                                    timeout=self._timeout,
                                    url=self._get_url(loc),
                                    verify=self._verify) as r:
                self.status_code = r.status_code
                if r.status_code == 500 and self._debug:
                    with open('debug_report.html', 'w') as fp:
                        fp.write(r.text)
                return r.status_code == 200
        except (AttributeError, KeyError, requests.exceptions.ConnectionError,
                requests.exceptions.Timeout, socket.timeout):
            self.status_code = None
        return False

    def report_result(
            self,
            classification='UNKNOWN',
            count=1,
            defect=None,
            failure=None,
            file_name=None,
            log='',
            plugin=None,
            name=None,
            loc='/crashstash/workreport/'
        ):
        """
        Report a result to a CrashStash Server.

        A result is made up of multiple components that will help triage
        and resolve the underlying issue.

        classification - string containing result's exploitability
        classification.

        count - integer representing the number of time the result was found.

        defect - string containing the major bucketing hash of the result.

        failure - string containing the minor bucketing hash of the result.

        file_name - string containing the absolute path of the test case.

        log - string usually containing stdout/stderr and debugger output
        (and other details).

        plugin - string containing the name of the plugin that was run to
        find the result.

        name - string containing the file name that should be used for the
        provided test case.

        loc - location on the server that WorkUnit will be reported to.

        Returns True if successful or False on a failed attempt.
        """
        if file_name is None or not os.path.isfile(file_name):
            return False
        try:
            with open(file_name, 'rb') as fp:
                data_hash = hashlib.sha1()
                while True:
                    data = fp.read(65536)
                    if not data:
                        break
                    data_hash.update(data)
                data = {
                    'classification':classification,
                    'Content-Length':fp.tell(),
                    'Content-Type':'application/octet-stream',
                    'count':count,
                    'defect':defect,
                    'failure':failure,
                    'has_result':'True',
                    'log':log,
                    'mac':self._get_mac_addr(),
                    'name':name,
                    'plugin_name':plugin,
                    'plugin_version':self._versions['plugin_versions'][plugin],
                    'result_hash':data_hash.hexdigest()
                }
                fp.seek(0)
                file = {'attachment':fp}
                with POSTRequestManager(data=data,
                                        files=file,
                                        timeout=self._timeout,
                                        url=self._get_url(loc),
                                        verify=self._verify) as r:
                    self.status_code = r.status_code
                    if r.status_code == 500 and self._debug:
                        with open('debug_report.html', 'w') as fp:
                            fp.write(r.text)
                return self.status_code == 200
        except (KeyError, requests.exceptions.ConnectionError,
                requests.exceptions.Timeout, socket.timeout):
            self.status_code = None
        return False

    def get_status_code(self):
        """
        Returns the HTTP status code of the most recent transaction.
        If an exception occurred None is returned.
        """
        return self.status_code

    def update_client_version(self, version):
        """Provides a way for nodes to update client version details."""
        self._versions['client_version'] = version
        self._versions['client_pending_update'] = ''
        self._save_versions()

    def update_plugin(self, dest_path='.'):
        """Unpacks the plugin update provided by the server."""
        try:
            with open(self._plugin_update, 'rb') as tfp:
                with tarfile.open(fileobj=tfp, mode='r:gz') as tar:
                    # TODO: look for abs paths and '..'
                    def is_within_directory(directory, target):
                        
                        abs_directory = os.path.abspath(directory)
                        abs_target = os.path.abspath(target)
                    
                        prefix = os.path.commonprefix([abs_directory, abs_target])
                        
                        return prefix == abs_directory
                    
                    def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
                    
                        for member in tar.getmembers():
                            member_path = os.path.join(path, member.name)
                            if not is_within_directory(path, member_path):
                                raise Exception("Attempted Path Traversal in Tar File")
                    
                        tar.extractall(path, members, numeric_owner=numeric_owner) 
                        
                    
                    safe_extract(tar, path=dest_path)
            pl_name, pl_version = self._versions['plugin_pending_update']
            self._versions['plugin_pending_update'] = None
            self._versions['plugin_versions'][pl_name] = pl_version
            self._save_versions()
        finally:
            os.remove(self._plugin_update)

