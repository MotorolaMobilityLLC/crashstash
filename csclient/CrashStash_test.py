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
csclient.Client unit tests

To run the tests: python3 -m unittest csclient/CrashStash_test.py
"""

__author__ = "Tyson Smith"

import csclient
import csclient.Testlib as Testlib
import hashlib
import os
import random
import shutil
import tempfile
import unittest

class TestClientRequest(unittest.TestCase):
    _test_version_file = 'test_vf.json'

    def tearDown(self):
        if os.path.isfile(self._test_version_file):
            os.remove(self._test_version_file)

    def test_request(self):
        port = random.randint(8000, 9000)
        cl = csclient.Client(
            port=port,
            scheme='http',
            version_file=self._test_version_file
        )
        with Testlib.TestServer(port) as srv:
            srv.set_mode('request')
            wu = cl.request()
        self.assertIsNone(cl.required_client_update())
        self.assertIsNone(cl.required_plugin_update())
        self.assertIsNotNone(wu)
        self.assertEqual(wu.allow_fuzzing, True)
        self.assertEqual(wu.duration, 1200)
        self.assertEqual(wu.iterations, 0)
        self.assertEqual(wu.plugin, Testlib.TEST_PLUGIN_NAME)
        self.assertEqual(wu.test_name, 'test_case_fn.bin')
        self.assertTrue(os.path.isfile(wu.test_file))
        with open(wu.test_file, 'rb') as fp:
            file_hash = hashlib.sha1(fp.read()).hexdigest()
        os.remove(wu.test_file)
        self.assertEqual(wu.test_hash, file_hash)

    def test_request_bad_url(self):
        port = random.randint(8000, 9000)
        cl = csclient.Client(
            port=port,
            scheme='http',
            version_file=self._test_version_file
        )
        with Testlib.TestServer(port):
            wu = cl.request('csclient/bad_url1234')
        self.assertIsNone(wu)

    def test_request_no_server(self):
        cl = csclient.Client(
            port=random.randint(8000, 9000),
            scheme='http',
            version_file=self._test_version_file
        )
        wu = cl.request()
        self.assertIsNone(wu)

    def test_request_server_hang(self):
        port = random.randint(8000, 9000)
        cl = csclient.Client(
            port=port,
            scheme='http',
            timeout=0.1,
            version_file=self._test_version_file
        )
        with Testlib.TestServer(port) as srv:
            srv.set_mode('server_hang')
            wu = cl.request()
        self.assertIsNone(wu)

    def test_request_client_update(self):
        port = random.randint(8000, 9000)
        cl = csclient.Client(
            port=port,
            scheme='http',
            version_file=self._test_version_file
        )
        with Testlib.TestServer(port) as srv:
            srv.set_mode('client_update')
            wu = cl.request()
        self.assertIsNone(wu)
        self.assertEqual(cl.get_client_version(), '')
        self.assertTrue(os.path.isfile(cl._client_update))
        os.remove(cl._client_update)
        self.assertEqual(cl._versions['client_pending_update'], '20140918_110500')

    def test_request_project_update(self):
        port = random.randint(8000, 9000)
        cl = csclient.Client(
            port=port,
            scheme='http',
            version_file=self._test_version_file
        )
        with Testlib.TestServer(port) as srv:
            srv.set_mode('plugin_update')
            wu = cl.request()
        self.assertIsNone(wu)
        self.assertTrue(os.path.isfile(cl._plugin_update))
        self.assertEqual(cl.get_plugin_version(Testlib.TEST_PLUGIN_NAME), '')
        self.assertEqual(cl.required_plugin_update(), (Testlib.TEST_PLUGIN_NAME, '20140918_110500', cl._plugin_update))
        self.assertEqual(cl._versions['plugin_pending_update'], (Testlib.TEST_PLUGIN_NAME, '20140918_110500'))
        cl.update_plugin()
        self.assertIsNone(cl.required_plugin_update())
        self.assertEqual(cl.get_plugin_version(Testlib.TEST_PLUGIN_NAME), '20140918_110500')
        self.assertTrue(os.path.isdir(Testlib.TEST_PLUGIN_NAME))
        shutil.rmtree(Testlib.TEST_PLUGIN_NAME)

    def test_request_fuzz(self):
        for _ in range(10): # increase this to 1000 for a longer run
            port = random.randint(6000, 9000)
            cl = csclient.Client(
                port=port,
                scheme='http',
                version_file=self._test_version_file
            )
            with Testlib.TestServer(port) as srv:
                srv.set_mode('fuzz')
                wu = cl.request()
            if wu and os.path.isfile(wu.test_file):
                os.remove(wu.test_file)
        if os.path.isfile(cl._plugin_update):
            os.remove(cl._plugin_update)
        if os.path.isfile(cl._client_update):
            os.remove(cl._client_update)


class TestClientReport(unittest.TestCase):
    _test_version_file = 'test_vf.json'

    def tearDown(self):
        if os.path.isfile(self._test_version_file):
            os.remove(self._test_version_file)

    def test_report_work_unit(self):
        port = random.randint(8000, 9000)
        cl = csclient.Client(
            port=port,
            scheme='http',
            version_file=self._test_version_file
        )
        wu = csclient.WorkUnit()
        wu.plugin = Testlib.TEST_PLUGIN_NAME
        wu.duration = 1200
        wu.iterations = 4567
        cl._versions['plugin_versions'][wu.plugin] = 'test_pl_v-1234'
        with Testlib.TestServer(port) as srv:
            srv.set_mode('report')
            response = cl.report_work(wu)
        self.assertTrue(response)

    def test_report_result(self):
        port = random.randint(8000, 9000)
        cl = csclient.Client(
            port=port,
            scheme='http',
            version_file=self._test_version_file
        )
        wu = csclient.WorkUnit()
        wu.plugin = Testlib.TEST_PLUGIN_NAME
        cl._versions['plugin_versions'][wu.plugin] = 'test_pl_v-1234'
        try:
            fd, wu.test_file = tempfile.mkstemp()
            os.close(fd)
            with open(wu.test_file, 'wb') as fp:
                fp.write(os.urandom(32) * 1024)
            with Testlib.TestServer(port) as srv:
                srv.set_mode('report')
                response = cl.report_result(
                    count=1,
                    defect='BADf00D',
                    failure='DEADBEEF',
                    file_name=wu.test_file,
                    log='',
                    plugin=wu.plugin,
                    name='test'
                )
            self.assertTrue(response)
        finally:
            if os.path.isfile(wu.test_file):
                os.remove(wu.test_file)

    def test_report_work_unit_fuzz(self):
        for _ in range(10): # increase this to 1000 for a longer test
            port = random.randint(6000, 9000)
            cl = csclient.Client(
                port=port,
                scheme='http',
                timeout=random.choice([0.001, 0.01]) if Testlib.Fuzz.dice(20) else None,
                version_file=self._test_version_file
            )
            wu = csclient.WorkUnit()
            if Testlib.Fuzz.dice():
                wu.allow_fuzzing = Testlib.Fuzz.string(None)
            elif not Testlib.Fuzz.dice():
                wu.allow_fuzzing = random.choice(['true', ''])

            if Testlib.Fuzz.dice():
                wu.duration = Testlib.Fuzz.int()
            elif not Testlib.Fuzz.dice():
                wu.duration = 1200

            if Testlib.Fuzz.dice():
                wu.iterations = Testlib.Fuzz.int()
            elif not Testlib.Fuzz.dice():
                wu.iterations = 1200

            if Testlib.Fuzz.dice():
                wu.plugin = Testlib.Fuzz.string(None)
            elif not Testlib.Fuzz.dice():
                wu.plugin = Testlib.TEST_PLUGIN_NAME
                cl._versions['plugin_versions'][wu.plugin] = 'test_pl_v-1234'

            if Testlib.Fuzz.dice():
                wu.test_name = Testlib.Fuzz.string(None)
            elif not Testlib.Fuzz.dice():
                wu.test_name = 'test_name'

            if Testlib.Fuzz.dice(20):
                wu = None
            with Testlib.TestServer(port) as srv:
                srv.set_mode('report')
                response = cl.report_work(wu)

    def test_report_result_fuzz(self):
        for _ in range(10): # increase this to 1000 for a longer test
            port = random.randint(6000, 9000)
            cl = csclient.Client(
                port=port,
                scheme='http',
                timeout=random.choice([0.001, 0.01]) if Testlib.Fuzz.dice(20) else None,
                version_file=self._test_version_file
            )
            wu = csclient.WorkUnit()
            args = {}
            if Testlib.Fuzz.dice():
                args['classification'] = Testlib.Fuzz.string(None)
            else:
                args['classification'] = 'UNKNOWN'

            if Testlib.Fuzz.dice():
                args['count'] = Testlib.Fuzz.int()
            else:
                args['count'] = 1

            if Testlib.Fuzz.dice():
                args['defect'] = Testlib.Fuzz.string(None)
            else:
                args['defect'] = 'BADf00D'

            if Testlib.Fuzz.dice():
                args['failure'] = Testlib.Fuzz.string(None)
            else:
                args['failure'] = 'DEADBEEF'

            if Testlib.Fuzz.dice():
                args['log'] = Testlib.Fuzz.string(None)
            else:
                args['log'] = 'test'

            if Testlib.Fuzz.dice():
                wu.plugin = Testlib.Fuzz.string(None)
            else:
                wu.plugin = Testlib.TEST_PLUGIN_NAME
                cl._versions['plugin_versions'][wu.plugin] = 'test_pl_v-1234'

            if Testlib.Fuzz.dice():
                wu.test_name = Testlib.Fuzz.string(None)
            else:
                wu.test_name = 'test_name'

            try:
                fd, wu.test_file = tempfile.mkstemp()
                os.close(fd)
                with open(wu.test_file, 'wb') as fp:
                    fp.write(os.urandom(random.choice([0, 1, 32])))
                with Testlib.TestServer(port) as srv:
                    srv.set_mode('report')
                    cl.report_result(
                        count=args['count'],
                        defect=args['defect'],
                        failure=args['failure'],
                        file_name=wu.test_file if not Testlib.Fuzz.dice() else Testlib.Fuzz.string(None),
                        log=args['log'],
                        plugin=wu.plugin,
                        name=wu.test_name
                    )
            finally:
                if os.path.isfile(wu.test_file):
                    os.remove(wu.test_file)

