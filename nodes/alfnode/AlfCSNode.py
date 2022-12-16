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
AlfCSNode.py

This is the code used to run an Alf CrashStash node. It uses the CrashStash
client module to handle communication with the CrashStash server and runs Alf
plugins using Alf.
"""

__author__ = "Tyson Smith"

import alf
import alf.debug
import alf.fuzz
import argparse
import csclient
import imp # deprecated as of python3.4
import importlib
import json
import logging
import logging.handlers
import os
import sys
import tarfile
import time

log = logging.getLogger('AlfCSNode')
log.propagate = False

class AlfCSNode(object):
    def __init__(self, server_addr, cert=None, plugin_name=None, port=443, scheme='https', test_mode=False):
        self._cert = cert
        self._ip_addr = server_addr
        self._port = port
        self._requested_pl = plugin_name
        self._report_unit = None
        self._results = None
        self._retry_delay = 300
        self._scheme = 'http' if scheme.lower() == 'http' else 'https'
        self._test_mode = test_mode
        self._version_file = 'test_version.json' if test_mode else 'cs_version.json'


    @staticmethod
    def _do_deletes():
        """
        Remove any files from the file system that the fuzzer or framework
        has marked for delete.
        """
        while True:
            f = alf.debug._common._get_delete_path()
            if f is None:
                break
            try:
                if os.path.isfile(f):
                    os.remove(f)
                elif os.path.isdir(f):
                    alf.rm_full_dir(f)
            except OSError:
                log.error('Failed to delete: %s', f)


    @staticmethod
    def _load_plugin(p_name):
        """Load Alf fuzzer"""
        try:
            p_mod = importlib.import_module('projects.%s' % p_name)
            if p_mod and len(alf._registered) < 1:
                imp.reload(p_mod) # required for python 3.2
                # As of python 3.4 imp.reload is deprecated
                # importlib.reload(p_mod) # new in python 3.4
        except ImportError:
            log.error('Failed to import plugin %s', p_name, exc_info=1)
            return None
        if len(alf._registered) != 1:
            log.error('%d plugins registered, expecting 1.', len(alf._registered))
            log.error('Plugin must register itself using alf.register()')
            return None
        plugin_cls = alf._registered.pop()
        if not issubclass(plugin_cls, alf.Fuzzer):
            raise TypeError('Expecting a Fuzzer, not %s' % type(plugin_cls))
        return plugin_cls


    def _perform_work(self, w_unit, working_dir, print_delay=60):
        """Handle running plugin and work from server using ALF"""
        log.info('Working directory: %s', working_dir)
        log.info('Duration: %d', w_unit.duration)
        log.info('Iterations: %d', w_unit.iterations)
        log.info('Allow fuzzing: %s', w_unit.allow_fuzzing)
        log.info('Test name: %s', w_unit.test_name)
        log.info('Test file: %s', w_unit.test_file)
        log.info('Test hash: %s', w_unit.test_hash)
        iterno = 0
        plugin = None
        self._results = dict()
        start_time = time.time()

        try:
            plugin_cls = self._load_plugin(w_unit.plugin)
            if plugin_cls is None:
                return

            plugin = plugin_cls(w_unit.test_file)
            tc_ext = os.path.splitext(w_unit.test_name)[1]
            os.chdir(working_dir)
            print_time = time.time() + 10
            end_time = w_unit.duration + start_time if w_unit.duration > 0 else 0
            log.info('Working until: %s', time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(end_time)))
            log.info('%-15s %-15s %s', 'Iterations', 'Rate', 'Results')

            while (end_time and time.time() < end_time) or (w_unit.iterations and iterno < w_unit.iterations):
                iterno += 1
                mutation_fn = 'mutation_%08X%s' % (iterno, tc_ext)
                result = plugin.do_iteration(mutation_fn, 1 if w_unit.allow_fuzzing else 0)
                if result is not None:
                    if not isinstance(result, alf.FuzzResult):
                        raise TypeError('Expecting FuzzResult, not %s' % type(result))
                    if result.classification != alf.debug.NOT_AN_EXCEPTION:
                        if not os.path.isfile(mutation_fn):
                            raise Exception('result reported before mutation written to disk')
                        f_id = '-'.join([str(result.classification), result.minor])
                        if f_id not in self._results:
                            self._results[f_id] = {
                                'classification':str(result.classification),
                                'count':0,
                                'defect':str(result.major),
                                'failure':str(result.minor),
                                'file_name':os.path.abspath(mutation_fn),
                                'log':result.text,
                                'name':os.path.basename(w_unit.test_name),
                                'plugin':str(w_unit.plugin)
                            }
                            # temporarily log result to file system
                            # used for viewing/debugging result before it is reported
                            # also saves results if unhandled exception occurs
                            with open('mutation_%08X.log.json' % iterno, 'w') as fp:
                                json.dump(self._results[f_id], fp, ensure_ascii=False, indent=2)
                        else:
                            # duplicate don't save file
                            alf.delete(mutation_fn)
                        self._results[f_id]['count'] += 1
                if result is None or result.classification == alf.debug.NOT_AN_EXCEPTION:
                    alf.delete(mutation_fn)
                self._do_deletes()

                if time.time() >= print_time: # print to console
                    print_time = time.time() + print_delay
                    elapsed_time = time.time() - start_time
                    rate = 0.0 if elapsed_time <= 0 else (1.0 * iterno / elapsed_time)
                    log.info('%-15d %-15.2f %d', iterno, rate, len(self._results))
        finally:
            elapsed_time = time.time() - start_time
            self._report_unit = csclient.WorkUnit()
            self._report_unit.duration = int(elapsed_time)
            self._report_unit.iterations = iterno
            self._report_unit.plugin = w_unit.plugin
            log.info('Ran %d iterations and found %d results in %.2fs', iterno, len(self._results), elapsed_time)
            if plugin is not None:
                plugin.cleanup()
                plugin.on_exit()
            self._do_deletes()


    def _unpack_archive(self, arc_name, dest_path='.'):
        try:
            with tarfile.open(name=arc_name, mode='r:gz') as tar:
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
        finally:
            if os.path.isfile(arc_name):
                os.remove(arc_name)


    def run(self):
        """
        This is the main loop. Operations managed here include:
            - communication with the server
            - requesting work
            - reporting work and results
            - client and plugin updates
            - preparation to perform work
            - post work cleanup
        """
        log.info('Ctrl+C to quit')
        try:
            base_dir = os.getcwd()
            done = False

            while not done:
                log.info('Current time: %s', time.strftime('%Y/%m/%d %H:%M:%S'))

                if self._scheme != 'https':
                    log.warning('Not using HTTPS')
                elif self._cert is None:
                    log.warning('Server certificate NOT provided')
                    log.warning('Server verification will NOT be performed')

                conn = csclient.Client(
                    addr=self._ip_addr,
                    cert=self._cert,
                    port=self._port,
                    scheme=self._scheme,
                    version_file=self._version_file
                )

                log.info('Client version: %s', conn.get_client_version())
                log.info('Contacting %s with work request...', self._ip_addr)
                if self._requested_pl is not None:
                    log.info('Plugin manually requested: %s', self._requested_pl)
                w_unit = conn.request(plugin=self._requested_pl)
                sc = conn.get_status_code()

                if sc is not None and sc != 200:
                    log.warning('Status code: %d', sc)
                    log.warning('Has this client been approved?')
                    if self._test_mode:
                        return False
                    log.warning('Waiting %d seconds', self._retry_delay)
                    time.sleep(self._retry_delay)
                    continue

                if conn.required_client_update():
                    cl_version, update_file = conn.required_client_update()
                    log.info('Client requires update to version: %s', cl_version)
                    self._unpack_archive(update_file)
                    conn.update_client_version(cl_version)
                    return True

                if conn.required_plugin_update():
                    pl_name = conn.required_plugin_update()[0]
                    log.info('%s will now be updated', pl_name)
                    conn.update_plugin(dest_path='projects')
                    continue

                if not type(w_unit) == type(csclient.WorkUnit()):
                    log.warning('Server transaction failed')
                    log.warning('Waiting %d seconds', self._retry_delay)
                    time.sleep(self._retry_delay)
                    continue

                log.info('Got work for %s', w_unit.plugin)
                working_dir = '%s_%s' % (time.strftime('%Y%m%d-%H-%M-%S'), w_unit.plugin)
                os.mkdir(working_dir)

                try:
                    self._perform_work(w_unit, working_dir)
                except KeyboardInterrupt:
                    done = True
                    log.info('User interrupted work')
                    log.info('Will exit following work report')
                log.info('Reporting work')

                while not conn.report_work(self._report_unit):
                    log.warning('Failed to report work waiting %d seconds', self._retry_delay)
                    time.sleep(self._retry_delay)

                log.info('%d result(s) to report', len(self._results))
                f_ids = list(self._results.keys())

                while f_ids:
                    if conn.report_result(**self._results[f_ids[0]]):
                        log.info('Result reported')
                        f_ids.pop(0)
                    else:
                        log.warning('Failed to report result waiting %d seconds', self._retry_delay)
                        time.sleep(self._retry_delay)

                log.info('Work report complete')
                os.chdir(base_dir)
                self._report_unit = None
                self._results = None
                alf.delete(w_unit.test_file)
                alf.delete(os.path.abspath(working_dir))
                self._do_deletes()

        except KeyboardInterrupt:
            log.info('User interrupted')
            done = True

        finally:
            pass #TODO: report errors

        return not done # indicate relaunch should be performed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CrashStash worker node')
    parser.add_argument('server_addr', help='CrashStash server address')
    parser.add_argument('--cert', default=None, help='Server certificate')
    parser.add_argument('--debug', default=False, action='store_true', help='')
    parser.add_argument('--plugin', default=None, help='')
    parser.add_argument('--port', default=443, type=int, help='')
    parser.add_argument('--scheme', default='https', help='')
    args = parser.parse_args()

    # configure logging
    log.setLevel(logging.DEBUG if args.debug else logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('[%(levelname).1s] %(message)s'))
    log.addHandler(ch)
    fh = logging.handlers.RotatingFileHandler(
        'AlfCSNode.log',
        maxBytes=512*1024,
        backupCount=1
    )
    fh.setFormatter(logging.Formatter('[%(levelname).1s] %(message)s'))
    log.addHandler(fh)
    logging.getLogger('requests.packages.urllib3').propagate = False
    logging.getLogger('urllib3.connectionpool').propagate = False

    log.info('Launching Alf CrashStash Node')

    if args.debug:
        log.debug('Debug logging is enabled')

    if args.cert is not None and not os.path.isfile(args.cert):
        log.error('%s does not exist', args.cert)
        sys.exit(0)

    node = AlfCSNode(
        args.server_addr,
        cert=args.cert,
        plugin_name=args.plugin,
        port=args.port,
        scheme=args.scheme
    )
    if node.run():
        log.info('Relaunch requested')
        sys.exit(1)
    sys.exit(0)
