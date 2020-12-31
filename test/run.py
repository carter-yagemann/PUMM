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

if __name__ == '__main__':
    unittest.main()
