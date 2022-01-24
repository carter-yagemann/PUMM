#!/usr/bin/env python3
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

if len(sys.argv) != 2:
    print("Usage: %s <output_filepath>" % os.path.basename(sys.argv[0]))
    sys.exit(1)

start_addr = None

with open('/proc/self/maps', 'r') as ifile:
    for line in ifile:
        if '[vdso]' in line:
            tokens = line.split(' ', 1)[0].split('-')
            start_addr = int(tokens[0], 16)
            end_addr = int(tokens[1], 16)
            size = end_addr - start_addr
            break

if start_addr is None:
    print("Failed to find vDSO in memory space", file=sys.stderr)
    sys.exit(1)

mem = open('/proc/self/mem', 'rb')
mem.seek(start_addr)
with open(sys.argv[1], 'wb') as ofile:
    ofile.write(mem.read(size))
