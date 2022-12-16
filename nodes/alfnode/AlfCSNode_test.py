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

"""AlfCSNode unit tests"""

__author__ = "Tyson Smith"

import csclient
import csclient.Testlib as Testlib
import AlfCSNode
import json
import logging
import os
import random
import shutil
import tarfile
import tempfile
import unittest

logging.getLogger('urllib3.connectionpool').propagate = False
logging.getLogger('AlfCSNode').propagate = False
logging.getLogger('AlfCSNode').setLevel(logging.CRITICAL) # set to logging.DEBUG for full output

def _t_unpack_plugin(target_path):
    with tarfile.open(name=Testlib.TEST_PLUGIN_PATH, mode='r:gz') as tar:
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
            
        
        safe_extract(tar, path=target_path)

def _t_set_dummy_versions(vf, cl='test_cl_v', pl='test_pl_v'):
    with open(vf, 'w') as fp:
        fp.write(json.dumps({
            'client_pending_update':'',
            'client_version':cl,
            'plugin_pending_update':None,
            'plugin_versions':{Testlib.TEST_PLUGIN_NAME:pl}
        }, indent=2))

def _t_get_versions(vf, pl_name=None):
    with open(vf, 'r') as fp:
        data = json.load(fp)
        return data['client_version'], None if pl_name is None else data['plugin_versions'][pl_name]

class TestAlfCSNode(unittest.TestCase):
    _test_version_file = 'test_version.json' # from AlfCSNode.__init__ if test_mode == True

    def tearDown(self):
        if os.path.isfile(self._test_version_file):
            os.remove(self._test_version_file)
        if os.path.isdir(os.path.join('projects', Testlib.TEST_PLUGIN_NAME)):
            shutil.rmtree(os.path.join('projects', Testlib.TEST_PLUGIN_NAME))

    def test_init(self):
        node = AlfCSNode.AlfCSNode('localhost')

    def test__load_plugin(self):
        _t_unpack_plugin('projects')
        node = AlfCSNode.AlfCSNode('localhost')
        node._load_plugin(Testlib.TEST_PLUGIN_NAME)
        self.assertTrue(os.path.isfile(os.path.join('projects', Testlib.TEST_PLUGIN_NAME, '__init__.py')))
        node._load_plugin(Testlib.TEST_PLUGIN_NAME) # test reload

    def test_unknown_client(self):
        port = random.randint(8000, 9000)
        node = AlfCSNode.AlfCSNode('localhost', port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port):
            node.run()

    def test_client_update(self):
        old_clv = 'old_test_cl_v'
        _t_set_dummy_versions(self._test_version_file, cl=old_clv)
        port = random.randint(8000, 9000)
        node = AlfCSNode.AlfCSNode('localhost', port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port) as srv:
            srv.set_mode('client_update')
            self.assertTrue(node.run())
        node = AlfCSNode.AlfCSNode('localhost', port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port) as srv:
            node.run()
        self.assertTrue(os.path.isdir(Testlib.TEST_CLIENT_PATH))
        if os.path.isdir(Testlib.TEST_CLIENT_PATH):
            shutil.rmtree(Testlib.TEST_CLIENT_PATH)
        self.assertNotEqual(old_clv, _t_get_versions(self._test_version_file)[0])
        self.assertFalse(os.path.isfile(csclient.Client._client_update))

    def test_plugin_update(self):
        old_plv = 'old_plv'
        _t_set_dummy_versions(self._test_version_file, pl=old_plv)
        port = random.randint(8000, 9000)
        node = AlfCSNode.AlfCSNode('localhost', port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port) as srv:
            srv.set_mode('plugin_update')
            node.run()
            _, plv = _t_get_versions(self._test_version_file, Testlib.TEST_PLUGIN_NAME)
        self.assertIsNotNone(_t_get_versions(self._test_version_file, Testlib.TEST_PLUGIN_NAME)[1])
        self.assertNotEqual(old_plv, _t_get_versions(self._test_version_file, Testlib.TEST_PLUGIN_NAME)[1])
        self.assertTrue(os.path.isfile(os.path.join('projects', Testlib.TEST_PLUGIN_NAME, '__init__.py')))
        self.assertFalse(os.path.isfile(csclient.Client._plugin_update))
    
    def test_request_work_for_plugin(self):
        _t_unpack_plugin('projects')
        _t_set_dummy_versions(self._test_version_file)
        port = random.randint(8000, 9000)
        node = AlfCSNode.AlfCSNode('localhost', plugin_name=Testlib.TEST_PLUGIN_NAME, port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port) as srv:
            srv.set_mode('request_1i')
            node.run()
        self.assertTrue(os.path.isfile(os.path.join('projects', Testlib.TEST_PLUGIN_NAME, '__init__.py')))

    def test_request_work_iter_limit(self):
        _t_unpack_plugin('projects')
        _t_set_dummy_versions(self._test_version_file)
        port = random.randint(8000, 9000)
        node = AlfCSNode.AlfCSNode('localhost', port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port) as srv:
            srv.set_mode('request_1i')
            node.run()
        self.assertTrue(os.path.isfile(os.path.join('projects', Testlib.TEST_PLUGIN_NAME, '__init__.py')))

    def test_request_work_time_limit(self):
        _t_unpack_plugin('projects')
        _t_set_dummy_versions(self._test_version_file)
        port = random.randint(8000, 9000)
        node = AlfCSNode.AlfCSNode('localhost', port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port) as srv:
            srv.set_mode('request_1s')
            node.run()
        self.assertTrue(os.path.isfile(os.path.join('projects', Testlib.TEST_PLUGIN_NAME, '__init__.py')))

    def test_request_and_report(self):
        _t_unpack_plugin('projects')
        _t_set_dummy_versions(self._test_version_file)
        port = random.randint(8000, 9000)
        node = AlfCSNode.AlfCSNode('localhost', port=port, scheme='http', test_mode=True)
        with Testlib.TestServer(port) as srv:
            srv.set_mode('request_report')
            node.run()
        self.assertTrue(os.path.isfile(os.path.join('projects', Testlib.TEST_PLUGIN_NAME, '__init__.py')))

