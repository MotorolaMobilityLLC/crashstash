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
CrashStash Server test.py

Running tests
test: python3 manage.py test csserver
profile: python3 -m cProfile -s tottime manage.py test csserver | grep 'views'
coverage: coverage3 run --source=csserver/views.py ./manage.py test csserver
"""

__author__ = "Tyson Smith"

import datetime
import hashlib
import json
import os
import random
import string
import tempfile
from django.core.urlresolvers import reverse
from django.db.utils import IntegrityError
from django.test import TestCase
from csserver.models import Classification, Client, ClientVersion
from csserver.models import Plugin, PluginTest, PluginVersion, Result
from csserver.models import Test, TriageState, WorkUnit

def _t_add_client(approved=True, platform='linux', mac=None):
    mac = mac if mac else ':'.join(['%02X' % random.randint(0, 255) for _ in range(6)])
    client = Client(
        approved=approved,
        mac_addr=mac,
        ip_addr='127.0.0.1',
        last_seen=datetime.datetime.now(),
        platform=platform
    )
    client.save()
    return client

def _t_add_plugin(
        name,
        file_name,
        test_data=None,
        platform='linux',
        weight=1,
        no_version=False):
    test_data = test_data if test_data is not None else os.urandom(10)
    with open(file_name, 'wb') as fp:
        fp.write(test_data)
    pl = Plugin(
        data=file_name,
        name=name,
        platform=platform,
        weight=weight
    )
    pl.save()
    if not no_version:
        pv = _t_add_plugin_version(pl)
    else:
        pv = None
    return (pl, pv)

def _t_add_plugin_version(plugin, date=None):
    if date is None:
        date = datetime.datetime.now()
    pv = PluginVersion(
        date=date,
        name='_'.join(
            [plugin.name, 'plv', '%08x' % random.randint(0, 0xFFFFFFFF)]),
        plugin=plugin
    )
    pv.save()
    return pv

def _t_add_plugin_test(plugin, testcase, allow_fuzzing=True):
    plt = PluginTest(
        allow_fuzzing=allow_fuzzing,
        plugin=plugin,
        test=testcase
    )
    plt.save()
    return plt

def _t_add_test(file_name, test_data=None, name=None, is_private=None):
    name = name if name is not None else os.path.basename(file_name)
    test_data = test_data if test_data is not None else os.urandom(32)
    with open(file_name, 'wb') as fp:
        fp.write(test_data)
    tc = Test(
        data=file_name,
        file_hash=hashlib.sha1(test_data).hexdigest(),
        is_private=is_private,
        name=name
    )
    tc.save()
    return tc

def _t_add_triage_states():
    TriageState(name='Ignored').save()
    TriageState(name='Logged').save()
    TriageState(name='New').save()
    TriageState(name='Not Reproducible').save()
    TriageState(name='Refresh').save()

def _t_add_classifications():
    Classification(display='Exploitable', value='EXPLOITABLE').save()
    Classification(display='Memory Limit', value='MEMORY_LIMIT').save()
    Classification(
        display='Probably Exploitable',
        value='PROBABLY_EXPLOITABLE').save()
    Classification(
        display='Probably Not Exploitable',
        value='PROBABLY_NOT_EXPLOITABLE').save()
    Classification(display='Time Limit', value='TIMEOUT').save()
    Classification(display='Unknown', value='UNKNOWN').save()

def _t_add_result(
        defect,
        failure,
        plugin,
        file_name,
        data_size=32,
        test_data=None,
        name=None,
        triage='New',
        cls='UNKNOWN',
        count=1,
        log='blah'
    ):
    name = name if name is not None else os.path.basename(file_name)
    test_data = test_data if test_data is not None else os.urandom(data_size)
    with open(file_name, 'wb') as fp:
        fp.write(test_data)
    r = Result(
        classification=Classification.objects.get(value=cls),
        count=count,
        data=file_name,
        defect=defect,
        failure=failure,
        file_hash=hashlib.sha1(test_data).hexdigest(),
        log=log,
        name=name,
        plugin=plugin,
        triage_state=TriageState.objects.get(name=triage)
    )
    r.save()


def _t_add_work_unit(client, pl_version, pl_test, duration=1200, iterations=0):
    work_unit = WorkUnit(
        client=client,
        duration=duration,
        iterations=iterations,
        plugin_test=pl_test,
        plugin_version=pl_version

    )
    work_unit.save()
    return work_unit

def _t_update_client(file_name, test_data=b'test'):
    with open(file_name, 'wb') as fp:
        fp.write(test_data)
    cv = ClientVersion(data=file_name)
    cv.save()
    return cv.version_string()

def _t_client_request(
        mac=None,
        platform='linux',
        plugins='',
        version=None):
    return {
        'mac': mac if mac else ':'.join(['%02X' % random.randint(0, 255) for _ in range(6)]),
        'client_version': version,
        'plugin_versions': plugins,
        'platform': platform
    }

def _t_create_result(cls=None, count=None, defect=None, failure=None, name=None, log=None, size_kb=1):
    fd, r_file = tempfile.mkstemp()
    os.close(fd)
    cls = cls if cls is not None else Classification.objects.all().order_by('?')[:1][0].value
    count = count if count is not None else random.randint(1, 100)
    defect = defect if defect is not None else hashlib.sha1(os.urandom(4)).hexdigest().lower()
    failure = failure if failure is not None else hashlib.sha1(os.urandom(4)).hexdigest().lower()
    name = name if name is not None else os.path.basename(r_file)
    result = {
        'classification':cls,
        'count':count,
        'defect':defect,
        'failure':failure,
        'file_name':os.path.basename(r_file),
        'log':'log data',
        'name':name,
        'temp_fs_name':r_file # WARNING: remember to delete this when finished
    }
    file_hash = hashlib.sha1()
    data = os.urandom(16) * 64
    with open(r_file, 'wb') as fp:
        for _ in range(size_kb):
            fp.write(data)
            file_hash.update(data)
    result['result_hash'] = file_hash.hexdigest().lower()
    return result

def _t_should_fuzz(odds=10):
    return random.randint(1, odds) == 1

def _t_int_fuzz(valid=10):
    return random.choice([
        (2 ** random.randint(1, 64)) * random.choice([-1, 1]),
        -1,
        0,
        1,
        valid,
        '',
        _t_big_string(),
        0xFFFFFFFF,
        0.1,
        0.999999999999,
        random.choice(string.printable)
    ])

def _t_str_fuzz(valid='test'):
    return random.choice([
        '',
        valid,
        _t_big_string(),
        random.choice(string.printable),
        '%s' % os.urandom(1)
    ])

def _t_big_string(printable=False):
    if printable or _t_should_fuzz(2):
        return random.choice(string.printable) * (2 ** random.randint(8, 20))
    return '%s' % os.urandom(1) * (2 ** random.randint(8, 20))

class CrashStashViewTests(TestCase):
    pass

class CrashStashRequestTests(TestCase):
    client_dir = 'client_version'
    client_file = None
    f_cleanup = None
    plugin_dir = 'plugins'
    result_dir = 'results'
    test_dir = 'test_cases'

    def setUp(self):
        _t_add_classifications()
        _t_add_triage_states()
        if not os.path.isdir(self.client_dir):
            os.mkdir(self.client_dir)
        if not os.path.isdir(self.plugin_dir):
            os.mkdir(self.plugin_dir)
        if not os.path.isdir(self.result_dir):
            os.mkdir(self.result_dir)
        if not os.path.isdir(self.test_dir):
            os.mkdir(self.test_dir)
        self.client_file = os.path.join(self.client_dir, 'test_client.tar.gz')
        self.f_cleanup = []

    def tearDown(self):
        for f_name in self.f_cleanup:
            if os.path.isfile(f_name):
                os.remove(f_name)
        for each in Test.objects.all():
            each.data.delete()
        for each in ClientVersion.objects.all():
            each.data.delete()
        for each in Plugin.objects.all():
            each.data.delete()
        for each in Result.objects.all():
            each.data.delete()

    def test_request_work_get(self):
        """Report 400 on invalid get request."""
        response = self.client.get('/csserver/workrequest/')
        self.assertEqual(response.status_code, 400)

    def test_request_initial_request_unknown_client(self):
        """Report 400 on request from an unknown client."""
        cr = _t_client_request()
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Client.objects.count(), 1)

    def test_request_initial_request_no_approval(self):
        """Report 400 on request from a non-approved client."""
        cr = _t_client_request()
        _t_add_client(mac=cr['mac'], approved=False)
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Client.objects.count(), 1)

    def test_request_no_mac(self):
        """Report 400 when client mac missing from request"""
        cr = _t_client_request()
        cr['mac'] = ''
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Client.objects.count(), 0)

    def test_request_no_mac_existing_clients(self):
        """Report 400 when client mac missing from request with other clients"""
        cr = _t_client_request(mac=None)
        _t_add_client(mac=cr['mac'], approved=True)
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Client.objects.count(), 1)

    def test_request_client_out_of_date(self):
        """Return 200 and update file for out dated client"""
        test_data = b'test'
        latest_version = _t_update_client(self.client_file, test_data=test_data)
        cr = _t_client_request()
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, test_data)
        self.assertEqual(response.get('client_version', None), latest_version)

    def test_request_no_server_side_plugins(self):
        """Return 400 - no plugins are available"""
        latest_version = _t_update_client(self.client_file)
        cr = _t_client_request(version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(response.content), 0)

    def test_request_plugins_disabled(self):
        """Return 400 - no plugins are enabled"""
        latest_version = _t_update_client(self.client_file)

        _t_add_plugin('test_pl', os.path.join(self.plugin_dir, 'pl_file_test.tar.gz'), weight=0)

        cr = _t_client_request(version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)

    def test_request_plugin_no_client_side_plugins(self):
        """Return 200 and update file for missing"""
        latest_version = _t_update_client(self.client_file)

        pl_name = 'test_pl_name'
        pl_data = b'test_pl_data'
        pl, pv = _t_add_plugin(pl_name, os.path.join(self.plugin_dir, 'pl_file_test.tar.gz'), pl_data)

        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))

        plt = _t_add_plugin_test(pl, tc)

        cr = _t_client_request(version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, pl_data)
        self.assertIsNone(response.get('client_version', None))
        self.assertEqual(response.get('plugin_name', None), pl_name)
        self.assertEqual(response.get('plugin_version', None), pv.name)

    def test_request_plugin_out_of_date(self):
        """Return 200 and update file for out of date plugin"""
        latest_version = _t_update_client(self.client_file)

        pl_name = 'test_pl_name'
        pl_data = b'test_pl_data'
        pl, pv = _t_add_plugin(
            pl_name,
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz'),
            pl_data
        )

        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))

        plt = _t_add_plugin_test(pl, tc)

        cl_plugins = json.dumps({pl_name:'old', 'other':'blah'})
        cr = _t_client_request(plugins=cl_plugins, version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, pl_data)
        self.assertIsNone(response.get('client_version', None))
        self.assertEqual(response.get('plugin_name', None), pl_name)
        self.assertEqual(response.get('plugin_version', None), pv.name)

    def test_request_work_no_tests(self):
        """Return 400 because no tests are available"""
        latest_version = _t_update_client(self.client_file)

        pl_name = 'test_pl_name'
        pl, pv = _t_add_plugin(
            pl_name,
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )

        cl_plugins = json.dumps({pl_name:pv.name, 'other':'blah'})
        cr = _t_client_request(plugins=cl_plugins, version=latest_version)
        cr['plugin_request'] = pl.name
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(response.get('client_version', None))
        self.assertIsNone(response.get('plugin_name', None))
        self.assertIsNone(response.get('plugin_version', None))

    def test_request_work(self):
        """Return 200 and a complete work unit"""
        latest_version = _t_update_client(self.client_file)

        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc_fname = os.path.join(self.test_dir, 'test_case_name.dat')
        tc_data = os.urandom(32)
        tc = _t_add_test(tc_fname, tc_data)

        plt = _t_add_plugin_test(pl, tc)

        cl_plugins = json.dumps({pl.name:pv.name, 'other':'blah'})
        cr = _t_client_request(plugins=cl_plugins, version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get('client_version', None))
        self.assertIsNotNone(response.get('plugin_name'))
        self.assertIsNone(response.get('plugin_version', None))
        self.assertEqual(response.get('test_name', None), os.path.basename(tc_fname))
        self.assertEqual(response.get('test_hash', None), hashlib.sha1(tc_data).hexdigest())
        self.assertEqual(response.content, tc_data)
        self.assertTrue(bool(int(response.get('allow_fuzzing', '0'))))
        self.assertEqual(response.get('iterations', None), '0')
        self.assertGreater(int(response.get('duration')), 0)

    def test_request_work_non_fuzzable(self):
        """Return 200 and a complete work unit with a non fuzzable test case"""
        latest_version = _t_update_client(self.client_file)

        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )

        tc_fname = os.path.join(self.test_dir, 'test_case_name.dat')
        tc_data = os.urandom(8)
        tc = _t_add_test(tc_fname, tc_data)

        plt = _t_add_plugin_test(pl, tc, allow_fuzzing=False)

        cl_plugins = json.dumps({pl.name:pv.name, 'other':'blah'})
        cr = _t_client_request(plugins=cl_plugins, version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get('client_version', None))
        self.assertIsNotNone(response.get('plugin_name'))
        self.assertIsNone(response.get('plugin_version', None))
        self.assertEqual(response.get('test_name', None), os.path.basename(tc_fname))
        self.assertEqual(response.get('test_hash', None), hashlib.sha1(tc_data).hexdigest())
        self.assertEqual(response.content, tc_data)
        self.assertFalse(bool(int(response.get('allow_fuzzing', '0'))))
        self.assertEqual(response.get('iterations', None), '1')
        self.assertEqual(response.get('duration', None), '0')

    def test_request_work_for_plugin(self):
        """Return 200 request work for a specific plugin request"""
        latest_version = _t_update_client(self.client_file)

        pl_1, pv_1 = _t_add_plugin(
            'test_pl_1_name',
            os.path.join(self.plugin_dir, 'pl1_file_test.tar.gz')
        )
        pl_2, pv_2 = _t_add_plugin(
            'test_pl_2_name',
            os.path.join(self.plugin_dir, 'pl2_file_test.tar.gz')
        )

        tc_fname = os.path.join(self.test_dir, 'test_case_name.dat')
        tc_data = os.urandom(8)
        tc = _t_add_test(tc_fname, tc_data)

        _t_add_plugin_test(pl_1, tc)
        _t_add_plugin_test(pl_2, tc)

        cl_plugins = json.dumps({pl_1.name:pv_1.name, pl_2.name:pv_2.name})

        cr = _t_client_request(plugins=cl_plugins, version=latest_version)
        _t_add_client(mac=cr['mac'])
        cr['plugin_request'] = pl_1.name
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get('client_version', None))
        self.assertEqual(response.get('plugin_name'), pl_1.name)
        self.assertIsNone(response.get('plugin_version', None))
        self.assertEqual(response.get('test_name', None), os.path.basename(tc_fname))
        self.assertEqual(response.get('test_hash', None), hashlib.sha1(tc_data).hexdigest())
        self.assertEqual(response.content, tc_data)
        self.assertEqual(response.get('allow_fuzzing', None), '1')
        self.assertEqual(response.get('iterations', None), '0')
        self.assertGreater(int(response.get('duration')), 0)

        cr['plugin_request'] = pl_2.name
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get('client_version', None))
        self.assertEqual(response.get('plugin_name'), pl_2.name)
        self.assertIsNone(response.get('plugin_version', None))
        self.assertEqual(response.get('test_name', None), os.path.basename(tc_fname))
        self.assertEqual(response.get('test_hash', None), hashlib.sha1(tc_data).hexdigest())
        self.assertEqual(response.content, tc_data)
        self.assertEqual(response.get('allow_fuzzing', None), '1')
        self.assertEqual(response.get('iterations', None), '0')
        self.assertGreater(int(response.get('duration')), 0)

    def test_request_work_refresh(self):
        """Return 200 and a complete refresh work unit
        """
        latest_version = _t_update_client(self.client_file)

        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        plt = _t_add_plugin_test(pl, tc)

        r_name = 'some_name.dat'
        r_data = os.urandom(8)
        _t_add_result(
            hashlib.sha1(b'a').hexdigest(),
            hashlib.sha1(b'b').hexdigest(),
            pl,
            os.path.join(self.result_dir, 'result_data_file.dat'),
            test_data=r_data,
            name=r_name,
            triage='Refresh'
        )

        cl_plugins = json.dumps({pl.name:pv.name, 'other':'blah'})
        cr = _t_client_request(plugins=cl_plugins, version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get('client_version', None))
        self.assertIsNotNone(response.get('plugin_name'))
        self.assertIsNone(response.get('plugin_version', None))
        self.assertEqual(response.get('test_name', None), r_name)
        self.assertEqual(response.get('test_hash', None), hashlib.sha1(r_data).hexdigest())
        self.assertEqual(response.content, r_data)
        self.assertFalse(response.get('allow_fuzzing', None))
        self.assertEqual(response.get('duration', None), '0')
        self.assertEqual(response.get('iterations', None), '1')


    def test_request_work_plugin_disabled_and_no_tests(self):
        """
        Return 400 - Two plugins are created one without plugin tests and
        the other with a weight of zero
        """
        latest_version = _t_update_client(self.client_file)

        # create plugin with no plugin tests
        _t_add_plugin(
            'test_pl_nt_name',
            os.path.join(self.plugin_dir, 'pl_nt_file_test.tar.gz')
        )

        # create plugin with plugin tests
        pl_name = 'test_pl_name'
        pl, pv = _t_add_plugin(
            pl_name,
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz'),
            weight=0
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        plt = _t_add_plugin_test(pl, tc)

        cl_plugins = json.dumps({pl_name:pv.name, 'other':'blah'})
        cr = _t_client_request(plugins=cl_plugins, version=latest_version)
        _t_add_client(mac=cr['mac'])
        response = self.client.post('/csserver/workrequest/', cr)
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(response.get('client_version', None))
        self.assertIsNone(response.get('plugin_name', None))
        self.assertIsNone(response.get('plugin_version', None))

    def test_request_fuzz(self):
        """
        Create and send fuzzy request data. This is just looking for errors.
        """
        latest_version = _t_update_client(self.client_file)
        test_clients = []
        for _ in range(50):
            test_clients.append(
                _t_add_client(
                    approved=False if _t_should_fuzz() else True,
                    platform='other' if _t_should_fuzz() else 'linux'
                )
            )

        pl_names = []
        plv_names = {}
        for _ in range(100): # it is very unlikely there will be more than 100 plugins
            pl_names.append('pl_0x%08x' % random.randint(0, 0xFFFFFFFF))
            pl, pv = _t_add_plugin(
                pl_names[-1],
                os.path.join(self.plugin_dir, 'pl_file_test_0x%08x.tar.gz' % random.randint(0, 0xFFFFFFFF)),
                weight=random.choice([0, 1, 1, 1, 1, 1, 1, 2]),
                no_version=True
            )
            plv_names[pl.name] = []
            for _ in range(random.randint(0, 10)):
                pv = _t_add_plugin_version(pl)
                plv_names[pl.name].append(pv.name)

            for _ in range(random.randint(0, 15)):
                tc_fname = os.path.join(self.test_dir, 'tcase_0x%08x.dat' % random.randint(0, 0xFFFFFFFF))
                tc = _t_add_test(tc_fname, os.urandom(10))
                _t_add_plugin_test(pl, tc, allow_fuzzing=not _t_should_fuzz(5))

        for _ in range(100): # for a longer test set this to 1000
            pl_name = random.choice(pl_names)
            plv_list = plv_names[pl_name]
            cr = _t_client_request(version=latest_version)
            if not _t_should_fuzz():
                _t_add_client(mac=cr['mac'])
            if _t_should_fuzz():
                cr['client_version'] = _t_str_fuzz()
            if _t_should_fuzz():
                cr['plugin_versions'] = _t_str_fuzz()
            elif _t_should_fuzz(5):
                cl_plugins = {}
                for _ in range(10, random.choice([len(pl_names), 100])):
                    if _t_should_fuzz(5) and plv_list:
                        cl_plugins[_t_str_fuzz()] = random.choice(plv_list)
                    elif _t_should_fuzz(3) and plv_list:
                        cl_plugins[pl_name] = random.choice(plv_list)
                    else:
                        cl_plugins[pl_name] = _t_str_fuzz()
                cr['plugin_versions'] = json.dumps(cl_plugins)
            else:
                cr['plugin_versions'] = json.dumps({pl_name:plv_list[-1] if plv_list else ''})
            if _t_should_fuzz():
                cr['mac'] = _t_str_fuzz()
            if _t_should_fuzz():
                cr['platform'] = _t_str_fuzz()
            if _t_should_fuzz():
                cr['plugin_request'] = _t_str_fuzz()
            elif _t_should_fuzz(8):
                cr['plugin_request'] = pl_name
            if _t_should_fuzz():
                cr[_t_str_fuzz()] = _t_str_fuzz()
            _ = self.client.post('/csserver/workrequest/', cr)

        self.assertFalse(Client.objects.filter(mac_addr='').exists())
        self.assertFalse(Client.objects.filter(platform='').exists())

class CrashStashReportTests(TestCase):
    client_dir = 'client_version'
    client_file = None
    f_cleanup = None
    plugin_dir = 'plugins'
    result_dir = 'results'
    test_dir = 'test_cases'

    def setUp(self):
        _t_add_classifications()
        _t_add_triage_states()
        if not os.path.isdir(self.client_dir):
            os.mkdir(self.client_dir)
        if not os.path.isdir(self.plugin_dir):
            os.mkdir(self.plugin_dir)
        if not os.path.isdir(self.result_dir):
            os.mkdir(self.result_dir)
        if not os.path.isdir(self.test_dir):
            os.mkdir(self.test_dir)
        self.client_file = os.path.join(self.client_dir, 'test_client.tar.gz')
        self.f_cleanup = []

    def tearDown(self):
        for f_name in self.f_cleanup:
            if os.path.isfile(f_name):
                os.remove(f_name)
        for each in Test.objects.all():
            each.data.delete()
        for each in ClientVersion.objects.all():
            each.data.delete()
        for each in Plugin.objects.all():
            each.data.delete()
        for each in Result.objects.all():
            each.data.delete()

    def test_report_work_unit_multiple_empty(self):
        """Report 200 - multiple work units with no results"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        total_iters = 0
        total_duration = 0

        for work_unit_number in range(1, 10):
            _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
            report = {
                'duration': random.randint(1, 1200),
                'iterations': random.randint(1, 10000),
                'mac': cl.mac_addr,
                'plugin_name':pl.name,
                'plugin_version': pv.name
            }
            response = self.client.post('/csserver/workreport/', report)
            self.assertEqual(response.status_code, 200)
            wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
            self.assertEqual(len(wu), 1)
            wu = wu[0]
            self.assertIsNotNone(wu.end_time)
            self.assertEqual(wu.duration, report['duration'])
            total_duration += report['duration']
            self.assertEqual(wu.iterations, report['iterations'])
            total_iters += report['iterations']
            self.assertLessEqual(wu.created_time, wu.end_time)
            self.assertEqual(Result.objects.count(), 0)
            pv = PluginVersion.objects.get(pk=pv.pk)
            self.assertEqual(pv.duration, total_duration)
            self.assertEqual(pv.iterations, total_iters)

    def test_report_work_unit_twice(self):
        """Report 400 - report same work unit two times"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
        report = {
            'duration': 1200,
            'iterations': 1,
            'mac': cl.mac_addr,
            'plugin_name':pl.name,
            'plugin_version': pv.name
        }

        response = self.client.post('/csserver/workreport/', report)
        self.assertEqual(response.status_code, 200)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        self.assertEqual(len(Result.objects.all()), 0)

        response = self.client.post('/csserver/workreport/', report)
        self.assertEqual(response.status_code, 200)
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_work_unit(self):
        """Report 200 - work unit and result"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
        result = _t_create_result(count=1, size_kb=1024*20) # huge 20 MB test case
        report = {
            'duration':1200,
            'iterations':1,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'log':result['log'],
            'name':result['name'],
            'result_hash':result['result_hash']
        }

        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 200)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        r = Result.objects.all()
        self.assertEqual(len(r), 1)
        r = r[0]
        self.assertEqual(r.classification, Classification.objects.get(value=report['classification']))
        self.assertEqual(r.count, report['count'])
        self.assertEqual(r.defect, report['defect'])
        self.assertEqual(r.failure, report['failure'])
        self.assertEqual(r.file_hash, report['result_hash'])
        self.assertEqual(r.name, report['name'])
        self.assertEqual(r.log, report['log'])
        self.assertEqual(r.triage_state, TriageState.objects.get(name='New'))
        self.assertTrue(os.path.isfile(r.data.name))
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_work_unit_refresh(self):
        """
        Report 200 - work unit with a result for a result that
        requires a refresh
        """
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
        result = _t_create_result(count=1)

        # this is the result that will be reported
        report = {
            'duration':23,
            'iterations':1,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'name':result['name'],
            'log':result['log'],
            'result_hash':result['result_hash']
        }

        # add the result that will be refreshed
        _t_add_result(
            report['defect'],
            report['failure'],
            pl,
            os.path.join(self.result_dir, 'some_name_1.dat'),
            cls=report['classification'],
            count=1,
            triage='Refresh'
        )

        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 200)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        r = Result.objects.all()
        self.assertEqual(len(r), 1)
        r = r[0]
        self.assertEqual(r.classification, Classification.objects.get(value=report['classification']))
        self.assertEqual(r.count, 2)
        self.assertEqual(r.defect, report['defect'])
        self.assertEqual(r.failure, report['failure'])
        self.assertEqual(r.file_hash, report['result_hash'])
        self.assertEqual(r.name, report['name'])
        self.assertEqual(r.log, report['log'])
        self.assertEqual(r.triage_state, TriageState.objects.get(name='New'))
        self.assertTrue(os.path.isfile(r.data.name))
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_work_unit_multiple_results(self):
        """Report 200 - work unit with multiple results"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))

        for report_number in range(1, 10):
            result = _t_create_result(count=1)
            report = {
                'duration':1200,
                'iterations':10,
                'mac':cl.mac_addr,
                'has_result':True,
                'plugin_name':pl.name,
                'plugin_version':pv.name,
                'classification':result['classification'],
                'count':result['count'],
                'defect':result['defect'],
                'failure':result['failure'],
                'file_name':result['file_name'],
                'log':result['log'],
                'name':result['name'],
                'result_hash':result['result_hash']
            }

            with open(result['temp_fs_name'], 'rb') as fp:
                report['attachment'] = fp
                response = self.client.post('/csserver/workreport/', report)
            os.remove(result['temp_fs_name'])
            self.assertEqual(response.status_code, 200)
            wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
            self.assertEqual(len(wu), 1)
            wu = wu[0]
            self.assertIsNotNone(wu.end_time)
            self.assertEqual(wu.duration, report['duration'])
            self.assertEqual(wu.iterations, report['iterations'])
            self.assertLessEqual(wu.created_time, wu.end_time)
            self.assertEqual(Result.objects.count(), report_number)
            r = Result.objects.get(failure=report['failure'])
            self.assertEqual(r.classification, Classification.objects.get(value=report['classification']))
            self.assertEqual(r.count, report['count'])
            self.assertEqual(r.defect, report['defect'])
            self.assertEqual(r.failure, report['failure'])
            self.assertEqual(r.file_hash, report['result_hash'])
            self.assertEqual(r.name, report['name'])
            self.assertEqual(r.log, report['log'])
            self.assertEqual(r.triage_state, TriageState.objects.get(name='New'))
            self.assertTrue(os.path.isfile(r.data.name))
            pv = PluginVersion.objects.get(pk=pv.pk)
            self.assertEqual(pv.duration, report['duration'])
            self.assertEqual(pv.iterations, report['iterations'])

    def test_report_work_unit_no_repro(self):
        """
        Report 200 - work unit with a result for a existing result
        that is a no repro
        """
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
        result = _t_create_result(count=1)

        # this is the result that will be reported
        report = {
            'duration':100,
            'iterations':10,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'name':result['name'],
            'log':result['log'],
            'result_hash':result['result_hash']
        }

        # add the result that will be refreshed
        _t_add_result(
            report['defect'],
            report['failure'],
            pl,
            os.path.join(self.result_dir, 'some_name_1.dat'),
            cls=report['classification'],
            count=1,
            triage='Not Reproducible'
        )

        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 200)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        r = Result.objects.all()
        self.assertEqual(len(r), 1)
        r = r[0]
        self.assertEqual(r.classification, Classification.objects.get(value=report['classification']))
        self.assertEqual(r.count, 2)
        self.assertEqual(r.defect, report['defect'])
        self.assertEqual(r.failure, report['failure'])
        self.assertEqual(r.file_hash, report['result_hash'])
        self.assertEqual(r.name, report['name'])
        self.assertEqual(r.log, report['log'])
        self.assertEqual(r.triage_state, TriageState.objects.get(name='New'))
        self.assertTrue(os.path.isfile(r.data.name))
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_work_unit_ignored(self):
        """Report 200 - work unit with a result for a result that is Ignored"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
        result = _t_create_result(count=1)

        # this is the result that will be reported
        report = {
            'duration':100,
            'iterations':10,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'name':result['name'],
            'log':result['log'],
            'result_hash':result['result_hash']
        }

        # add the result that should not be refreshed
        _t_add_result(
            report['defect'],
            report['failure'],
            pl,
            os.path.join(self.result_dir, 'some_name_1.dat'),
            cls=report['classification'],
            triage='Ignored'
        )

        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 200)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        r = Result.objects.all()
        self.assertEqual(len(r), 1)
        r = r[0]
        self.assertEqual(r.classification, Classification.objects.get(value=report['classification']))
        self.assertEqual(r.count, 1)
        self.assertEqual(r.defect, report['defect'])
        self.assertEqual(r.failure, report['failure'])
        self.assertNotEqual(r.file_hash, report['result_hash'])
        self.assertEqual(r.triage_state, TriageState.objects.get(name='Ignored'))
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_result_no_work_unit(self):
        """Report 200 - report result without a work unit"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        result = _t_create_result(count=1)

        # this is the result that will be reported
        report = {
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'log':result['log'],
            'result_hash':result['result_hash']
        }

        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 200)
        self.assertFalse(WorkUnit.objects.filter(client=cl).exists())
        r = Result.objects.all()
        self.assertEqual(len(r), 1)
        r = r[0]
        self.assertEqual(r.classification, Classification.objects.get(value=report['classification']))
        self.assertEqual(r.count, 1)
        self.assertEqual(r.defect, report['defect'])
        self.assertEqual(r.failure, report['failure'])
        self.assertEqual(r.file_hash, report['result_hash'])
        self.assertEqual(r.name, report['file_name'])
        self.assertEqual(r.triage_state, TriageState.objects.get(name='New'))
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, 0)
        self.assertEqual(pv.iterations, 0)

    def test_report_work_unit_bad_test_hash(self):
        """Report 400 - work unit and result with bad test case hash"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
        result = _t_create_result(count=1)
        report = {
            'duration':100,
            'iterations':1,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'log':result['log'],
            'name':result['name'],
            'result_hash':'BADF00D'
        }

        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 400)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        self.assertEqual(Result.objects.count(), 0)
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_work_unit_refresh_matching_test_case(self):
        """
        Report 200 - work unit with a result with a matching test case that
        is reported from out of data plugin
        """
        cl = _t_add_client()
        pl, old_pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, old_pv, _t_add_plugin_test(pl, tc))
        result = _t_create_result(count=1)

        # this is the result that will be reported
        report = {
            'duration':23,
            'iterations':1,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':old_pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'log':result['log'],
            'result_hash':result['result_hash']
        }

        # add the result that will be refreshed
        with open(result['temp_fs_name'], 'rb') as fp:
            _t_add_result(
                report['defect'],
                report['failure'],
                pl,
                result['name'],
                test_data=fp.read(),
                cls=report['classification'],
                triage='Refresh'
            )

        pv = PluginVersion(
            name='new_plugin_%s' % hashlib.sha1(os.urandom(2)).hexdigest()[5],
            plugin=pl
        )
        pv.save()
        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 200)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        r = Result.objects.all()
        self.assertEqual(len(r), 1)
        r = r[0]
        self.assertEqual(r.classification.value, Classification.objects.get(value=report['classification']).value)
        self.assertGreater(r.count, report['count'])
        self.assertEqual(r.defect, report['defect'])
        self.assertEqual(r.failure, report['failure'])
        self.assertEqual(r.file_hash, report['result_hash'])
        self.assertEqual(r.name, report['file_name'])
        self.assertEqual(r.log, report['log'])
        self.assertEqual(r.triage_state.name, TriageState.objects.get(name='Refresh').name)
        self.assertTrue(os.path.isfile(r.data.name))
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, 0)
        self.assertEqual(pv.iterations, 0)
        pv = PluginVersion.objects.get(pk=old_pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_work_unit_no_test_case(self):
        """Report 400 - work unit and result missing test case"""
        cl = _t_add_client()
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        _t_add_work_unit(cl, pv, _t_add_plugin_test(pl, tc))
        result = _t_create_result(count=1)
        report = {
            'duration':100,
            'iterations':1,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'log':result['log'],
            'result_hash':'BADF00D'
        }
        response = self.client.post('/csserver/workreport/', report)
        self.assertEqual(response.status_code, 400)
        wu = WorkUnit.objects.filter(client=cl).order_by('-created_time')[:1]
        self.assertEqual(len(wu), 1)
        wu = wu[0]
        self.assertIsNotNone(wu.end_time)
        self.assertEqual(wu.duration, report['duration'])
        self.assertEqual(wu.iterations, report['iterations'])
        self.assertLessEqual(wu.created_time, wu.end_time)
        self.assertEqual(Result.objects.count(), 0)
        pv = PluginVersion.objects.get(pk=pv.pk)
        self.assertEqual(pv.duration, report['duration'])
        self.assertEqual(pv.iterations, report['iterations'])

    def test_report_result_multiple_times(self):
        """report same result two times"""
        cl = _t_add_client()
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        pl, pv = _t_add_plugin(
            'test_pl_name',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        _t_add_plugin(
            'test_pl_name_2',
            os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
        )
        plt = _t_add_plugin_test(pl, tc)

        result = _t_create_result(count=1)
        report = {
            'duration':1200,
            'iterations':10,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':result['count'],
            'defect':result['defect'],
            'failure':result['failure'],
            'file_name':result['file_name'],
            'log':result['log'],
            'name':result['name'],
            'result_hash':result['result_hash']
        }
        for _ in range(2):
            _t_add_work_unit(cl, pv, plt)
            with open(result['temp_fs_name'], 'rb') as fp:
                report['attachment'] = fp
                response = self.client.post('/csserver/workreport/', report)
            self.assertEqual(response.status_code, 200)
        os.remove(result['temp_fs_name'])
        r = Result.objects.all()
        self.assertEqual(len(r), 1)
        r = r[0]
        self.assertEqual(r.count, 2)
        self.assertEqual(Result.objects.filter(triage_state=TriageState.objects.get(name='New')).count(), 1)


    def test_report_defect_failure_mismatch(self):
        """
        Typically a failures should not have multiple defects, however a
        defect may be exposed by multiple unique failures. In other words
        the defect is derived from the failure so a failure should not have
        more than one defect. Verify this is enforced.
        """
        cl = _t_add_client()
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        pl, pv = _t_add_plugin('test_pl_name', os.path.join(self.plugin_dir, 'pl_file_test.tar.gz'))
        plt = _t_add_plugin_test(pl, tc)

        failure_hash = hashlib.sha1(b'failure_hash').hexdigest()
        result = _t_create_result(count=1)
        _t_add_result(
            hashlib.sha1(b'defect_1_hash').hexdigest(),
            failure_hash,
            pl,
            'file_name_doesnt_matter',
            cls=result['classification'],
            count=1,
            triage='Refresh'
        )
        self.assertEqual(Result.objects.filter(failure=failure_hash).count(), 1)
        report = {
            'duration':1200,
            'iterations':10,
            'mac':cl.mac_addr,
            'has_result':True,
            'plugin_name':pl.name,
            'plugin_version':pv.name,
            'classification':result['classification'],
            'count':1,
            'defect':hashlib.sha1(b'defect_2_hash').hexdigest(),
            'failure':failure_hash,
            'file_name':'file_name_doesnt_matter',
            'log':result['log'],
            'name':result['name'],
            'result_hash':result['result_hash']
        }
        with open(result['temp_fs_name'], 'rb') as fp:
            report['attachment'] = fp
            response = self.client.post('/csserver/workreport/', report)
        os.remove(result['temp_fs_name'])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Result.objects.count(), 1)
        r = Result.objects.filter(failure=failure_hash)
        self.assertEqual(r.count(), 1)
        self.assertEqual(r[0].count, 1)
        self.assertEqual(r[0].triage_state.name, TriageState.objects.get(name='Refresh').name)


    def test_report_fuzz(self):
        """Create and report fuzzy data. This is just looking for errors."""
        test_clients = []
        for _ in range(100):
            test_clients.append(
                _t_add_client(
                    approved=False if _t_should_fuzz() else True,
                    platform='other' if _t_should_fuzz() else 'linux'
                )
            )
        self.assertEqual(Client.objects.count(), 100)
        self.assertTrue(Client.objects.filter(platform='linux').exists())
        self.assertTrue(Client.objects.exclude(platform='linux').exists())
        approved_count = Client.objects.filter(approved=True).count()
        plugins = {}
        for i in range(5): # test with 5 plugins
            pl_name = 'test_pl_name_%04x' % i
            pl, pv = _t_add_plugin(
                pl_name,
                os.path.join(self.plugin_dir, 'pl_file_test.tar.gz')
            )
            plugins[pl_name] = {'plugin':pl, 'versions':[pv], 'tests':[]}
        tc = _t_add_test(os.path.join(self.test_dir, 'test_case_name.dat'))
        for pl_name in plugins.keys():
            plugins[pl_name]['tests'].append(_t_add_plugin_test(plugins[pl_name]['plugin'], tc))
            for i in range(random.randint(0, 10)):
                priv = plugins[pl_name]['plugin'] if _t_should_fuzz else None
                tc = _t_add_test(os.path.join(self.test_dir, 'tc_%s_%d.dat' % (pl_name, i)), is_private=priv)
                plugins[pl_name]['tests'].append(_t_add_plugin_test(plugins[pl_name]['plugin'], tc))
            for _ in range(random.randint(0, 10)):
                plugins[pl_name]['versions'].append(_t_add_plugin_version(plugins[pl_name]['plugin']))

        test_classes = Classification.objects.all()
        test_states = TriageState.objects.all()

        # for better fuzzing increase the iters to 5000 (default: 100 for quick test)
        for report_number in range(1, 100):
            cl = random.choice(test_clients)
            pl_name = random.choice(list(plugins.keys()))
            if not _t_should_fuzz():
                pv = random.choice(plugins[pl_name]['versions'])
                plt = random.choice(plugins[pl_name]['tests'])
                _t_add_work_unit(cl, pv, plt)
            result = _t_create_result()
            report = {}
            if not _t_should_fuzz():
                report['duration'] = _t_int_fuzz()
            if not _t_should_fuzz():
                report['iterations'] = _t_int_fuzz()
            if not _t_should_fuzz():
                report['mac'] = _t_str_fuzz(random.choice(test_clients).mac_addr) if _t_should_fuzz() else cl.mac_addr
            if not _t_should_fuzz():
                report['has_result'] = _t_str_fuzz('False') if _t_should_fuzz() else True
            if not _t_should_fuzz():
                report['plugin_name'] = _t_str_fuzz() if _t_should_fuzz() else pl_name
            if not _t_should_fuzz():
                report['plugin_version'] = _t_str_fuzz() if _t_should_fuzz() else random.choice(plugins[pl_name]['versions']).name
            if not _t_should_fuzz():
                report['classification'] = _t_str_fuzz() if _t_should_fuzz() else result['classification']
            if not _t_should_fuzz():
                report['count'] = _t_int_fuzz()
            if not _t_should_fuzz():
                report['defect'] = _t_str_fuzz('badbad') if _t_should_fuzz() else result['defect']
            if not _t_should_fuzz():
                report['failure'] = _t_str_fuzz('f00df00d') if _t_should_fuzz() else result['failure']
            if not _t_should_fuzz():
                report['file_name'] = _t_str_fuzz() if _t_should_fuzz() else result['file_name']
            if not _t_should_fuzz():
                report['log'] = _t_str_fuzz() if _t_should_fuzz() else result['log']
            if not _t_should_fuzz():
                report['name'] = _t_str_fuzz() if _t_should_fuzz() else result['name']
            if not _t_should_fuzz():
                report['result_hash'] = _t_str_fuzz() if _t_should_fuzz(15) else result['result_hash']
            if _t_should_fuzz():
                report[_t_str_fuzz()] = _t_str_fuzz()

            with open(result['temp_fs_name'], 'rb') as fp:
                if _t_should_fuzz(3):
                    _t_add_result(
                        result['defect'],
                        result['failure'],
                        plugins[pl_name]['plugin'],
                        result['file_name'],
                        test_data=fp.read() if not _t_should_fuzz() else os.urandom(10),
                        cls=random.choice(test_classes).value,
                        triage=random.choice(test_states).name,
                        count=random.choice([1, random.randint(1, 0x7FFFFFFF)]),
                        log=''
                    )
                fp.seek(0)
                if not _t_should_fuzz():
                    report['attachment'] = fp
                response = self.client.post('/csserver/workreport/', report)
            os.remove(result['temp_fs_name'])

        self.assertTrue(Result.objects.exists())
        self.assertFalse(Result.objects.filter(defect='').exists())
        self.assertFalse(Result.objects.filter(failure='').exists())
        self.assertFalse(Result.objects.filter(file_hash='').exists())
        self.assertFalse(Client.objects.filter(mac_addr='').exists())
        self.assertEqual(approved_count, Client.objects.filter(approved=True).count())
        self.assertFalse(Client.objects.filter(platform='').exists())
