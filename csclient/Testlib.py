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

"""Test helper classes and functions"""

__author__ = "Tyson Smith"

import hashlib
import http.server
import os
import random
import shutil
import string
import tempfile
import tarfile
import threading
import time

TEST_CLIENT_PATH = 'client_unpack_test_dir'
TEST_PLUGIN_NAME = 'TestPlugin'
TEST_PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '%s.tar.gz' % TEST_PLUGIN_NAME
)

class Fuzz(object):
    @staticmethod
    def dice(weight=10):
        return random.randint(1, weight) == 1

    @staticmethod
    def int(valid=10):
        return random.choice([
            -1,
            0,
            1,
            valid,
            '',
            Fuzz.big_string(),
            0xFFFFFFFF,
            0.1,
            0.999999999999,
            (2 ** random.randint(0, 20)) + random.randint(-5, 4),
            random.choice(string.printable)
        ])

    @staticmethod
    def string(valid='test'):
        return random.choice([
            '',
            valid,
            Fuzz.big_string(),
            random.choice(string.printable),
            '%s' % os.urandom(1)
        ])

    @staticmethod
    def big_string():
        return random.choice(string.printable) * random.choice([100] * 10 + [1000, 1024*1024])


class SimpleTestHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, *args, **kwargs):
        pass # disable server messages

    def do_GET(self):
        self.send_response(400)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        path = self.path.strip('/').split('/')
        if len(path) != 2 or path[0].lower() != 'crashstash':
            self.send_response(400)
        path = path[1].lower()
        mode = self.server.get_test_mode()
        #print(path)
        #print(mode)
        self.server.set_test_mode('reset')
        if path == 'workrequest' and mode in ('request', 'request_1i', 'request_1s', 'request_report'):
            test_data_size = 1024
            test_data = os.urandom(test_data_size)
            self.send_response(200)
            self.send_header('Connection', 'close')
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Transfer-Encoding', 'binary')
            self.send_header('Content-Disposition', 'attachment; filename="test_case_fn.bin"')
            self.send_header('Content-Length', '%d' % test_data_size)
            #
            if mode == 'request':
                self.send_header('allow_fuzzing', '1')
                self.send_header('duration', '1200')
                self.send_header('iterations', '0')

            elif mode == 'request_1i':
                self.send_header('allow_fuzzing', '0')
                self.send_header('duration', '0')
                self.send_header('iterations', '1')

            elif mode == 'request_1s':
                self.send_header('allow_fuzzing', '0')
                self.send_header('duration', '1')
                self.send_header('iterations', '0')

            elif mode == 'request_report':
                self.send_header('allow_fuzzing', '1')
                self.send_header('duration', '0')
                self.send_header('iterations', '12')

            self.server.set_test_mode('report')
            self.send_header('plugin_name', TEST_PLUGIN_NAME)
            self.send_header('test_hash', hashlib.sha1(test_data).hexdigest())
            self.send_header('test_name', 'test_case_fn.bin')
            self.end_headers()
            self.wfile.write(test_data)

        elif path == 'workrequest' and mode == 'client_update':
            self.send_response(200)
            temp_dir = tempfile.mkdtemp()
            with open(os.path.join(temp_dir, 'test_file'), 'wb') as fp:
                data = os.urandom(1024)
                for _ in range(1024):
                    fp.write(data)
                test_data_size = fp.tell()
            self.send_header('Connection', 'close')
            self.send_header('Content-type', 'application/x-gzip')
            self.send_header('Content-Transfer-Encoding', 'binary')
            self.send_header('Content-Disposition', 'attachment; filename="client_update.tar.gz"')
            self.send_header('Content-Length', '%d' % test_data_size)
            #
            self.send_header('client_version', '20140918_110500')
            self.end_headers()
            with tempfile.TemporaryFile() as fp:
                with tarfile.open(fileobj=fp, mode='w:gz') as tar:
                    tar.add(temp_dir, arcname=TEST_CLIENT_PATH)
                fp.seek(0)
                self.wfile.write(fp.read())
            shutil.rmtree(temp_dir)

        elif path == 'workrequest' and mode == 'plugin_update':
            self.send_response(200)
            self.send_header('Connection', 'close')
            self.send_header('Content-type', 'application/x-gzip')
            self.send_header('Content-Transfer-Encoding', 'binary')
            self.send_header('Content-Disposition', 'attachment; filename="plugin_update.tar.gz"')
            with open(TEST_PLUGIN_PATH, 'rb') as fp:
                data = fp.read()
            self.send_header('Content-Length', '%d' % len(data))
            #
            self.send_header('plugin_name', TEST_PLUGIN_NAME)
            self.send_header('plugin_version', '20140918_110500')
            self.end_headers()
            self.wfile.write(data)

        elif path == 'workrequest' and mode == 'server_hang':
            test_data_size = 1024
            test_data = os.urandom(test_data_size)
            self.send_response(200)
            self.send_header('Connection', 'close')
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Transfer-Encoding', 'binary')
            self.send_header('Content-Disposition', 'attachment; filename="test_case_fn.bin"')
            self.send_header('Content-Length', '%d' % test_data_size)
            #
            self.send_header('allow_fuzzing', '1')
            self.send_header('duration', '1200')
            self.send_header('iterations', '0')
            self.send_header('plugin_name', TEST_PLUGIN_NAME)
            self.send_header('test_hash', hashlib.sha1(test_data).hexdigest())
            self.send_header('test_name', 'test_case_fn.bin')
            self.end_headers()
            time.sleep(0.3)
            self.wfile.write(test_data)

        elif path == 'workreport' and mode == 'report':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.server.set_test_mode('report')
            #print(dir(self))
            #print(dir(self.server))
            #print(dir(self.headers))
            #print(self.headers.get('result_hash'))
            #print(self.headers)
            #print(hashlib.sha1(self.rfile.read()).hexdigest())

        elif path == 'workrequest' and mode == 'fuzz':
            test_data_size = random.choice([0, 1, 1024, 1024*1024])
            test_data = os.urandom(1) * test_data_size
            if Fuzz.dice():
                self.send_response(random.choice(list(self.responses.keys())))
            else:
                self.send_response(200)
            self.send_header('Connection', 'close')

            if Fuzz.dice():
                self.send_header('Content-Transfer-Encoding', random.choice(['base64', '8bit', '7bit']))
            elif not Fuzz.dice():
                self.send_header('Content-Transfer-Encoding', 'binary')
            self.send_header('Content-Disposition', 'attachment; filename="test_case_fn.bin"')

            if Fuzz.dice():
                self.send_header('Content-Length', str(Fuzz.int()))
            elif not Fuzz.dice():
                self.send_header('Content-Length', '%d' % test_data_size)

            if Fuzz.dice():
                self.send_header('Content-type', 'text/plain')
            elif not Fuzz.dice():
                self.send_header('Content-type', 'application/octet-stream')

            if Fuzz.dice():
                self.send_header('allow_fuzzing', Fuzz.string(''))
            elif not Fuzz.dice():
                self.send_header('allow_fuzzing', '1')

            if Fuzz.dice():
                self.send_header('duration', str(Fuzz.int()))
            elif not Fuzz.dice():
                self.send_header('duration', '1200')

            if Fuzz.dice():
                self.send_header('iterations', str(Fuzz.int()))
            elif not Fuzz.dice():
                self.send_header('iterations', '0')

            if Fuzz.dice():
                self.send_header('plugin_name', Fuzz.string())
            elif not Fuzz.dice():
                self.send_header('plugin_name', TEST_PLUGIN_NAME)

            if Fuzz.dice():
                self.send_header('test_hash', Fuzz.string())
            elif not Fuzz.dice():
                self.send_header('test_hash', hashlib.sha1(test_data).hexdigest())

            if Fuzz.dice():
                self.send_header('test_name', Fuzz.string())
            elif not Fuzz.dice():
                self.send_header('test_name', 'test_case_fn.bin')

            if Fuzz.dice(20):
                self.send_header('client_version', '20140918_110500')
            elif Fuzz.dice(20):
                self.send_header('client_version', Fuzz.string())

            if Fuzz.dice(30):
                self.send_header('plugin_name', Fuzz.string())
            elif Fuzz.dice(30):
                self.send_header('plugin_version', Fuzz.string())
            elif Fuzz.dice(30):
                self.send_header('plugin_name', TEST_PLUGIN_NAME)
                self.send_header('plugin_version', Fuzz.string())

            self.end_headers()
            if not Fuzz.dice():
                try:
                    self.wfile.write(test_data)
                except ConnectionResetError:
                    pass
        else:
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()


class TestHTTPServer(http.server.HTTPServer):
    _modes = (
        'client_update',
        'fuzz',
        'plugin_update',
        'request',
        'request_1i',
        'request_1s',
        'request_report',
        'report',
        'reset',
        'server_hang'
    )

    def __init__(self, *args, **kwargs):
        super(TestHTTPServer, self).__init__(*args, **kwargs)
        self._test_mode = None

    def get_test_mode(self):
        return self._test_mode

    def set_test_mode(self, mode):
        mode = mode.lower()
        if mode in self._modes:
            self._test_mode = None if mode == 'reset' else mode


class TestServer(threading.Thread):
    _httpd = None

    def __init__(self, port=8000):
        super(TestServer, self).__init__()
        self._port = port
        self._httpd = TestHTTPServer(('127.0.0.1', port), SimpleTestHandler)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc1, exc2, exc3):
        self._httpd.shutdown()
        self._httpd.socket.close()
        self.join()

    def run(self):
        self._httpd.serve_forever(poll_interval=0.1)

    def set_mode(self, new_mode):
        self._httpd.set_test_mode(new_mode)
