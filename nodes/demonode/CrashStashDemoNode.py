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
CrashStashDemoNode.py: CrashStash Demo Node

This is a simple example of how a CrashStash Node can be
used to interact with the CrashStash server. In this example
both a client and plugin update can be retrieved as well as a
work unit. Both a work unit and result can be reported back to
the server.

Keep in mind this is an example and it is meant to highlight
the layer between the CrashStash server and the fuzzing framework.

For example:
---------------------
| CrashStash Server |
--------------------- <- Server Machine
         ||
--------------------- <- Client Machine
| CrashStash Client |
---------------------
| CrashStash Node   |
---------------------
| Fuzzing Framework |
---------------------
| Fuzzer            |
---------------------

Each fuzzing framework should have its own CrashStash Node that will
automate the requests for work for the framework and also automate the
execution of the fuzzers for the framework.
"""

__author__ = "Tyson Smith"

import argparse
import hashlib
import json
import logging as log
import os
import random
import tempfile
import time

import csclient

class CSDemoNode(object):
    CONFIG = 'config.json' # Node configuration file

    def __init__(self, ip_addr, port, cert=None, scheme='http'):
        self._cert = cert
        self._ip_addr = ip_addr
        self._port = port
        self._scheme = scheme

    @staticmethod
    def _fake_client_update(version, file_name):
        """
        Updates CrashStash and Node code.

        This would normally unpack the zip and call an update script but since
        this is a very simple demo it only updates the client version info.
        """
        os.remove(file_name)
        try:
            with open(CSDemoNode.CONFIG, 'r') as fp:
                versions = json.load(fp)
            versions['client_version'] = version
            versions['client_pending_update'] = ''
            with open(CSDemoNode.CONFIG, 'w') as fp:
                fp.write(json.dumps(versions, indent=2))
            log.info('Client updated to version: %s', version)
        except (FileNotFoundError, KeyError, TypeError, ValueError) as e:
            log.error(e)
            log.error('Something has gone wrong :(')

    @staticmethod
    def _fake_plugin_update(pl_name, pl_version, file_name):
        """
        Updates a fuzzing plugin package.

        This would normally unpack the plugin zip to the correct location
        but since this is very simple a demo it only updates the version info.
        """
        os.remove(file_name)
        try:
            with open(CSDemoNode.CONFIG, 'r') as fp:
                versions = json.load(fp)
            versions['plugin_versions'][pl_name] = pl_version
            versions['plugin_pending_update'] = ()
            with open(CSDemoNode.CONFIG, 'w') as fp:
                fp.write(json.dumps(versions, indent=2))
            log.info('Plugin: %s updated to version: %s', pl_name, pl_version)
        except (FileNotFoundError, KeyError, TypeError, ValueError) as e:
            log.error(e)
            log.error('Something has gone wrong :(')

    def request(self, plugin_name=None):
        """
        Makes a request to the CrashStash server for a work unit.

        plugin_name is used to request work for a specific plugin. If None
        is used work for any active plugin can be assigned.

        Returns a WorkUnit or None if an update for the client or a plugin was
        received instead of a WorkUnit. None is also returned if there is a
        problem communicating with the server. None typically means try again.
        """
        c = csclient.Client(
            addr=self._ip_addr,
            cert=self._cert,
            port=self._port,
            scheme=self._scheme,
            debug=True
        )
        log.info('The current client version is: %s', c.get_client_version())
        log.info('Contacting server with work request...')
        if plugin_name is not None:
            log.info('Plugin manually requested: %s...', plugin_name)
        wu = c.request(plugin=plugin_name)
        sc = c.get_status_code()
        if sc is not None and sc != 200:
            log.warn('Status code: %d', sc)
        if c.required_client_update():
            # a client update is available, unpack it and return None
            # so another work request is made.
            log.info('Looks like the client needs to be updated.')
            new_version, file_name = c.required_client_update()
            self._fake_client_update(new_version, file_name)
            return None
        if c.required_plugin_update():
            # a plugin update is available, unpack it and return None
            # so another work request is made.
            pl_name, pl_version, pl_file = c.required_plugin_update()
            log.info('Looks like there is an update for %s.', pl_name)
            self._fake_plugin_update(pl_name, pl_version, pl_file)
            return None
        if not type(wu) == type(csclient.WorkUnit()):
            log.warn('Something went wrong expected a WorkUnit.')
            log.warn('Has this client been approved?')
            # wait to avoid hammering the server
            time.sleep(5)
            return None
        log.info('Received a work unit')
        log.info('plugin: %s', wu.plugin)
        log.info('for %d seconds or %d iterations (0 == no limit)', wu.duration, wu.iterations)
        log.info('use this test case: %s', wu.test_file)
        log.info('it should have this sha1 hash: %s', wu.test_hash)
        if wu.allow_fuzzing:
            log.info('it is %sfuzzable', '' if wu.allow_fuzzing else 'NOT ')
        os.remove(wu.test_file)
        return wu

    def report_work(self, wu):
        """
        report_work in this example will populate the WorkUnit with dummy data
        and report the work back to the CrashStash server.
        """
        # populate the dummy work unit
        wu.duration = wu.duration if wu.duration else random.randint(1, 1200)
        wu.iterations = wu.iterations if wu.iterations else random.randint(1, 40000)

        log.info('Reporting WorkUnit...')
        log.info('Plugin: %s', wu.plugin)
        log.info('Duration: %d', wu.duration)
        log.info('Iterations: %d', wu.iterations)
        log.info('Contacting server with work report...')
        
        c = csclient.Client(
            addr=self._ip_addr,
            cert=self._cert,
            port=self._port,
            scheme=self._scheme,
            debug=True
        )
        # attempt to report work unit to server
        if c.report_work(wu):
            log.info('Work reported')
        else:
            # TODO: a retry mechanism should be added
            sc = c.get_status_code()
            if sc is not None and sc != 200:
                log.warn('Status code: %d', sc)
            log.warn('Failed to report work unit')

    def report_result(self, wu):
        """
        report_result in this example will create a dummy result and report
        it back to the CrashStash server.
        """
        log.info('Generating a result')

        # generate random dummy test case
        fd, test_file = tempfile.mkstemp()
        os.close(fd)
        with open(test_file, 'wb') as fp:
            fp.write(os.urandom(2**random.randint(0, 20)))
        try:
            # generate random dummy result
            result = {
                'classification':random.choice(['UNKNOWN', 'EXPLOITABLE', 'TIMEOUT']),
                'count':random.randint(1, 10),
                'defect':hashlib.sha1(os.urandom(random.randint(0, 1))).hexdigest(),
                'failure':hashlib.sha1(os.urandom(random.randint(1, 3))).hexdigest(),
                'file_name':test_file,
                'log':'stuff happened...\nstack()\ntrace()\nfoo()\n',
                'name':'test_file.bin',
                'plugin':wu.plugin
            }
            c = csclient.Client(
                addr=self._ip_addr,
                cert=self._cert,
                port=self._port,
                scheme=self._scheme,
                debug=True
            )
            log.info('Reporting Result...')
            if c.report_result(**result):
                log.info('Result reported')
            else:
                # TODO: a retry mechanism should be added
                sc = c.get_status_code()
                if sc is not None and sc != 200:
                    log.warn('Status code: %d', sc)
                log.warn('Failed to report result')
        finally:
            os.remove(test_file)

    def run(self, plugin=None):
        """
        run is a simple main loop. This is where CrashStash and the fuzzing
        framework would interface.
        """

        # for the purpose of this demo this will run 5 times instead of say an
        # endless loop
        for _ in range(10):
            work_unit = self.request(plugin_name=plugin)
            if work_unit is None:
                continue # no work available so try again

            # In a production node this is where the work unit data would
            # be passed to the fuzzing framework and the framework would
            # perform the work

            # Once this work for a work unit is complete the work is reported
            self.report_work(work_unit)

            # Any results that were found are then also reported
            for _ in range(random.randint(0, 5)): # random number of results
                self.report_result(work_unit)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CrashStash Demo Node 5000!')
    parser.add_argument('--cert', dest='cert', default=None)
    parser.add_argument('--https', action='store_const', const='https', dest='scheme', default='http')
    parser.add_argument('--ip', dest='ip', default='127.0.0.1')
    parser.add_argument('--port', dest='port', default=8000, type=int)
    parser.add_argument('-p', '--plugin', dest='plugin_name', default=None)
    parser.add_argument('-q', '--quiet', dest='verbose', action='store_false', default=True)
    parser.add_argument('-r', '--reset', dest='reset', action='store_true', default=False)

    args = parser.parse_args()
    if args.verbose:
        print('')
        log.basicConfig(format='[%(levelname).1s] %(message)s', level=log.INFO)
        log.info('Welcome to CrashStash Demo Node <blink>5000!</blink>')

    if args.reset:
        if os.path.isfile(CSDemoNode.CONFIG):
            os.remove(CSDemoNode.CONFIG)
        log.info('Reset client to fresh state')

    node = CSDemoNode(args.ip, args.port, cert=args.cert, scheme=args.scheme)
    node.run(plugin=args.plugin_name)

