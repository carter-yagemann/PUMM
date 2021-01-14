#!/usr/bin/env python
#
# Copyright 2021 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import subprocess
import sys
import unittest

# hack so unit tests work from any directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/analysis')))

import maps

class TestMaps(unittest.TestCase):

    test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'data'))
    test_file = os.path.join(test_dir, 'maps/firefox-esr')
    test_entries = 99

    def setUp(self):
        if not os.path.isfile(self.test_file):
            self.skipTest("Cannot find test file: %s" % self.test_file)

    def test_parsing(self):
        map = maps.read_maps(self.test_file)
        self.assertEqual(len(map), self.test_entries)

class TestAnalysis(unittest.TestCase):

    run_script = os.path.join(os.path.dirname(__file__), '../src/analysis/analysis.py')
    traces_dir = os.path.join(os.path.dirname(__file__), 'data')
    truth = {
        'eup-test': {'traces': ['1/0.ptxed.gz', '2/4.ptxed.gz'],
                     'timeout': 60},
    }

    def setUp(self):
        if not os.path.isfile(self.run_script):
            self.skipTest("Missing script: %s" % self.run_script)
        if not os.path.isdir(self.traces_dir):
            self.skipTest("Missing directory: %s" % self.traces_dir)

    def do_analysis_test(self, name):
        # get path to traces, make sure they all exist
        traces = [os.path.join(self.traces_dir, name, trace) for
                      trace in self.truth[name]['traces']]
        for trace in traces:
            if not os.path.isfile(trace):
                self.skipTest("Missing trace: %s" % trace)

        cmd = [sys.executable, self.run_script] + traces

        ret = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=self.truth[name]['timeout'])

        self.assertEqual(ret.returncode, 0)

        # TODO - Right now we only check that the analysis
        # completes in a reasonable amount of time because
        # the implementation is incomplete. Eventually we'll
        # check the results.

    def test_eup_test(self):
        self.do_analysis_test('eup-test')

if __name__ == '__main__':
    unittest.main()
